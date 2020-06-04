
/*******************************************************************************
 * Copyright 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include "easylogging++.h"

#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mstream.pb.h>

#include "common_broker_thread.h"
#include "common_socket.h"
#include "msl_streaming_lib.h"
#include "mstream_grpc_server_thread.h"
#include <grpcpp/grpcpp.h>
#include <unistd.h>

#include "opencv2/imgcodecs.hpp"

using namespace imif;
using namespace mstream;

#define MSTREAM_TEST_DECODE_PERFORMACE_ONLY 0

services::msl::StreamingLibrary::AsyncService *base_call_data::s_service;

grpc::ServerCompletionQueue *base_call_data::s_cq;

std::set<void *> base_call_data::s_all_calls;

// keep pointers to the servers' service and cq, common to all calls.
void base_call_data::init(services::msl::StreamingLibrary::AsyncService *service, grpc::ServerCompletionQueue *cq)
{
    s_service = service;
    s_cq = cq;
}

base_call_data::base_call_data() : m_status(PROCESS)
{
    s_all_calls.insert(this); // keep track of allocated callDatas
}

base_call_data::~base_call_data() {}

void base_call_data::finish(bool ok) {}

void base_call_data::deallocate()
{
    s_all_calls.erase(this);
    delete this;
}

// cast only if ptr point to an allocated callData
base_call_data *base_call_data::validate_cast(void *ptr)
{
    if (s_all_calls.count(ptr)) {
        return static_cast<base_call_data *>(ptr);
    }
    return nullptr;
}

ping_call_data::ping_call_data() : m_responder(&m_ctx)
{
    s_service->RequestPing(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void ping_call_data::process(GrpcServerThread *this_thread)
{
    if (m_status == PROCESS) {
        LOG(INFO) << "Received ping";
        new ping_call_data();

        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }

        deallocate();
    }
}
connect_call_data::connect_call_data() : m_responder(&m_ctx)
{
    s_service->RequestConnect(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void connect_call_data::process(GrpcServerThread *this_thread)
{
    if (m_status == PROCESS) {
        LOG(TRACE) << "Received CONNECT";
        new connect_call_data();

        m_status = FINISH;

        m_output.set_client_id(this_thread->next_client_id());

        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }

        deallocate();
    }
}

infer_call_data::infer_call_data() : m_responder(&m_ctx)
{
    s_service->RequestInfer(&m_ctx, &m_request, &m_responder, s_cq, s_cq, this);
}

void infer_call_data::process(GrpcServerThread *this_thread)
{
    if (m_status == PROCESS) {
        new infer_call_data();

        prepare_frames(this_thread);

        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);

        process_frames(this_thread);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void infer_call_data::prepare_frames(GrpcServerThread *this_thread)
{
    //LOG(TRACE) << "infer_call_data::prepare_frames()";
    m_work_items.clear();
    m_output.clear_frame_infer_response();
    for (auto &frame_data : m_request.frames_data().frame_data()) {
        auto frame_infer_response = m_output.add_frame_infer_response();
        if (!frame_infer_response) {
            LOG(ERROR) << "Failed to allocate frame_infer_response";
            return;
        }
        frame_infer_response->set_ok(false);
        frame_infer_response->set_client_context(frame_data.client_context());
    }

    if (!this_thread->enabled()) {
        LOG(DEBUG) << "disabled";
        return;
    }

    auto flow_id = m_request.flow_id();

    if (this_thread->flows().find(flow_id) == this_thread->flows().end()) {
        LOG(ERROR) << "Flow ID " << flow_id << " unknown.";
        return;
    }
    auto &flow_context = this_thread->flows()[flow_id];

    LOG(TRACE) << "Got " << m_request.frames_data().frame_data_size() << " frames"
               << " for flow " << m_request.flow_id();

    auto frame_format = m_request.frame_format();
    if ((frame_format != imif::messages::enums::FrameFormat::JPEG) && (frame_format != imif::messages::enums::FrameFormat::RGB)) {
        LOG(ERROR) << "Got infer request with unrecognized frame format.";
        return;
    }

    if (m_request.frames_data().frame_data_size() < 1) {
        LOG(INFO) << "Got infer request with no frames";
        return;
    }

    auto pool = flow_context.pool;
    if (!pool) {
        LOG(FATAL) << "Shared memory pool is missing.";
        return;
    }

    int32_t response_index = -1;
    for (const auto &frame_data : m_request.frames_data().frame_data()) {
        ++response_index;
        auto &payload = frame_data.payload();
        if (payload.length() == 0) {
            LOG(ERROR) << "Payload size 0, skipping.";
            continue;
        }

        int image_height;
        int image_width;
        size_t image_bytesize;
        switch (frame_format) {
        case (imif::messages::enums::FrameFormat::JPEG): {
            if (!get_image_dimensions(payload, image_height, image_width)) {
                LOG(ERROR) << "Unable to decode image size. Skipping.";
                this_thread->add_dropped_bytes(payload.length());
                continue;
            }
            image_bytesize = image_height * image_width * 3;
        }; break;
        case (imif::messages::enums::FrameFormat::RGB): {
            image_height = frame_data.height();
            image_width = frame_data.width();
            image_bytesize = image_height * image_width * 3;
            if ((image_height < 1) || (image_width < 1)) {
                LOG(ERROR) << "Image size is missing or incorrect. Skipping. "
                           << "Offending frame client context: " << frame_data.client_context();
                this_thread->add_dropped_bytes(payload.length());
                continue;
            }
            if (image_bytesize != payload.size()) {
                LOG(ERROR) << "Payload size " << payload.size() << " does not match expected size " << image_bytesize
                           << " for image with dimenstions " << image_height << "x" << image_width << " Skipping. "
                           << "Offending frame client context: " << frame_data.client_context();
                this_thread->add_dropped_bytes(payload.length());
                continue;
            }
        } break;
        default:
            LOG(ERROR) << "Unrecognized frame format";
            continue;
        }

        std::shared_ptr<common::shmem_buff> write_ptr = pool->alloc_buff(payload.length());
        if (!write_ptr) {
            LOG(ERROR) << "There is not enough space to allocate " << image_bytesize << " bytes";
            this_thread->add_dropped_bytes(payload.length());
            continue;
        }
        std::shared_ptr<cv::Mat> rgbMat = std::make_shared<cv::Mat>(image_height, image_width, CV_8UC3, write_ptr->ptr());
        m_work_items.emplace_back(infer_work_item(rgbMat, write_ptr, frame_data));
        m_output.mutable_frame_infer_response(response_index)->set_ok(true);
    }
}

void infer_call_data::process_frames(GrpcServerThread *this_thread)
{
    LOG(TRACE) << "infer_call_data::process_frames() with " << m_work_items.size() << " work items.";
    messages::types::EventFrameReady event_frame_ready_msg;
    uint64_t total_bytes = 0;
    uint64_t total_frames = 0;

    auto flow_id = m_request.flow_id();
    auto frame_format = m_request.frame_format();
    auto &flow_context = this_thread->flows()[flow_id];
    auto frame_number = __sync_fetch_and_add(&(flow_context.highest_frame_number), m_work_items.size());

    for (auto &work_item : m_work_items) {
        auto start_time = std::chrono::steady_clock::now();
        auto frame_data = work_item.frame_data;
        std::string *payload = frame_data.mutable_payload();
        std::string image_stream_format;

        switch (frame_format) {
        case (imif::messages::enums::FrameFormat::JPEG): {
            image_stream_format = "jpeg";
        } break;
        case (imif::messages::enums::FrameFormat::RGB): {
            image_stream_format = "rgb";
        } break;
        default:
            LOG(ERROR) << "Unrecognized frame format.";
            continue;
        }

        std::copy_n(payload->c_str(), payload->length(), work_item.rgbMat->data);

        auto now = std::chrono::steady_clock::now();
        this_thread->add_time_spent_decoding_usec(std::chrono::duration_cast<std::chrono::microseconds>(now - start_time).count());

        if (flow_context.next_stages.size() == 0) {
            continue;
        }

        auto efr = event_frame_ready_msg.add_efr();
        auto fi = efr->mutable_frame_info();
        fi->mutable_flow()->set_id(m_request.flow_id());
        for (auto next_stage_id : flow_context.next_stages)
            fi->mutable_flow()->add_stage_id(next_stage_id);
        fi->mutable_frame()->set_frame_num(frame_number);
        fi->mutable_frame()->set_client_context(frame_data.client_context());
        fi->mutable_frame()->set_is_scaled(false);
        fi->mutable_frame()->set_width(work_item.rgbMat->cols);
        fi->mutable_frame()->set_height(work_item.rgbMat->rows);
        fi->mutable_frame()->set_format(image_stream_format);
        efr->mutable_buff()->CopyFrom(*(work_item.rgb_shmem_buff));

        ++frame_number;
        total_bytes += work_item.rgb_shmem_buff->buff_size();

        LOG(DEBUG) << "process_frames: prepared frame number " << frame_number << " client context " << frame_data.client_context();
    }
    total_bytes += event_frame_ready_msg.ByteSizeLong();
#if MSTREAM_TEST_DECODE_PERFORMACE_ONLY
    auto status = true;
#else
    auto status =
        common::broker_thread::send_msg(this_thread->broker_socket(), messages::enums::INPUT_JPEG_READY, event_frame_ready_msg);
    LOG(TRACE) << "send_msg returned " << status;

#endif
    if (status) {
        this_thread->add_sent_bytes(total_bytes);
        this_thread->add_sent_frames(total_frames);
    } else {
        LOG(ERROR) << "infer_call_data::process_frames failed sending MSTREAM_EVENT_IMG_READY";
        this_thread->add_dropped_bytes(total_bytes);
    }

    if (!status || MSTREAM_TEST_DECODE_PERFORMACE_ONLY) {
        for (auto &work_item : m_work_items) {
            if (!work_item.rgb_shmem_buff->drop()) {
                LOG(FATAL) << "Unable to drop unsent work item.";
            }
        }
    }
    return;
}

receive_stream_call_data::receive_stream_call_data() : m_reader_writer(&m_ctx)
{
    s_service->RequestStreamFile(&m_ctx, &m_reader_writer, s_cq, s_cq, this);
    m_status = INIT;
}

void receive_stream_call_data::process(GrpcServerThread *this_thread)
{
    if (m_status == INIT) {
        new receive_stream_call_data();
        m_reader_writer.Read(&m_chunk, this);
        m_status = READY;
    } else if (m_status == READY) {
        auto success = this_thread->send_chunk(m_chunk.content(), m_chunk.flow_id());
        m_status = PROCESS;
        m_response.set_response(success);
        m_reader_writer.Write(m_response, this);
    } else if (m_status == PROCESS) {
        m_chunk.mutable_content()->clear();
        m_reader_writer.Read(&m_chunk, this);
        m_status = READY;
    } else if (m_status == FINISH) {
        deallocate();
    }
}

void receive_stream_call_data::finish(bool ok)
{
    m_reader_writer.Finish(grpc::Status::OK, this);
    m_status = FINISH;
}

GrpcServerThread::GrpcServerThread(const std::string broker_uds_path) : m_broker_uds_path(broker_uds_path) {}

bool GrpcServerThread::init()
{
    LOG(TRACE) << "GrpcServerThread::init()";

    // Connect to the message broker
    if (!m_broker_uds_path.empty()) {
        m_broker_socket = std::make_shared<common::SocketClient>(m_broker_uds_path);
        if (!m_broker_socket) {
            LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds_path;
            return false;
        } 
        const auto error_msg = m_broker_socket->getError();
        if (!error_msg.empty()) {
            LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds_path << " [ERROR: " << error_msg << "]";
            m_broker_socket.reset();
            return false;
        } 
        LOG(DEBUG) << "new socket with broker " << m_broker_uds_path;
    }

    if (!m_broker_socket->isOpen()) {
        LOG(FATAL) << " GrpcServerThread, unable to connect to broker";
        return false;
    }
    return true;
}

void GrpcServerThread::clear()
{
    m_sources.clear();
    m_flows.clear();
}

bool GrpcServerThread::set_listening_port(const std::string port) { return set_listening_port(std::atoi(port.c_str())); }

bool GrpcServerThread::set_listening_port(const int32_t port)
{
    if ((port < 0) || (port > 65535)) {
        LOG(ERROR) << "Invalid port number " << port;
        return false;
    }

    if (port == 0) {
        return set_listening_port(mstream::streaming_client::default_port);
    }

    if (port == m_port && m_server_started)
        return true; // no change

    m_port = port;

    if (m_server_started) {
        shutdown_grpc_server();
    }
    start_grpc_server();

    return true;
}

bool GrpcServerThread::start_grpc_server()
{
    //LOG(TRACE) << "GrpcServerThread::start_grpc_server()";

    if (m_cq || m_server) {
        LOG(ERROR) << "Server already running";
        return false;
    }

    std::string server_address = std::string("0.0.0.0:") + std::to_string(m_port);
    grpc::ServerBuilder builder;

    m_service = new services::msl::StreamingLibrary::AsyncService();

    // Changing GRPC connection maintaining behavior:
    // builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 2000);
    // builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 1000);
    // builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
    // builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, INT_MAX);
    // builder.AddChannelArgument(GRPC_ARG_HTTP2_BDP_PROBE, 1);
    // builder.AddChannelArgument(GRPC_ARG_MAX_CONNECTION_IDLE_MS , 1000);
    builder.SetMaxReceiveMessageSize(mstream::streaming_client::max_message_size);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(m_service);
    m_cq = builder.AddCompletionQueue();
    m_server = builder.BuildAndStart();

    LOG(INFO) << "MSTREAM grpc::Server listening on " << server_address;

    base_call_data::init(m_service, m_cq.get());

    new ping_call_data();
    new connect_call_data();
    new infer_call_data();
    new listen_call_data(this);
    new subscribe_call_data(this);
    new receive_stream_call_data();

    m_server_started = true;

    return true;
}

bool GrpcServerThread::enable()
{
    m_enabled = true;
    return true;
}

GrpcServerThread::~GrpcServerThread() { on_thread_stop(); }

void GrpcServerThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop";
    shutdown_grpc_server();
}

void GrpcServerThread::shutdown_grpc_server()
{
    LOG(TRACE) << "GrpcServerThread::shutdown_grpc_server()";
    if (m_server && m_cq) {
        void *ignored_tag;
        bool ignored_ok;
        m_cq->Shutdown();
        m_server->Shutdown();
        do {
        } while (m_cq->Next(&ignored_tag, &ignored_ok));

        m_server = nullptr;
        m_cq = nullptr;
        delete m_service;
        m_service = nullptr;
        m_server_started = false;
    }
}

bool GrpcServerThread::work()
{
    if (!m_server_started) {
        UTILS_SLEEP_MSEC(500);
        return true;
    }

    void *tag;
    bool ok;
    bool ret = m_cq->Next(&tag, &ok);
    if (should_stop) {
        return true;
    }

    if (ret) {
        base_call_data *call_data = dynamic_cast<base_call_data *>(base_call_data::validate_cast(tag));
        if (call_data) {
            if (ok) {
                call_data->process(this);
            } else {
                // !ok means a stream has ended with WritesDone
                call_data->finish(ok);
            }
        }
    } else {
        LOG(DEBUG) << "Server detected aborted request. ret=" << ret << " ok=" << ok;
    }
    return true;
}

void GrpcServerThread::before_stop()
{
    if (should_stop) {
        if (m_server) {
            m_server->Shutdown();
        }
        if (m_cq) {
            m_cq->Shutdown();
        }
        m_server_started = false;
    }
}

bool GrpcServerThread::add_flow(uint32_t flow_id, const messages::types::Stage &stage)
{
    if (m_flows.find(flow_id) != m_flows.end()) {
        LOG(ERROR) << "Can't create shmem for grpc flow_id " << flow_id << ". Already exist!";
        return false;
    }

    // Create shared memory
    size_t shm_size_mb = 90;
    size_t shm_size = shm_size_mb * 1024 * 1024;

    int pid = common::os_utils::get_pid();
    int shmkey = (pid << 8) | flow_id;
    auto pool = std::make_shared<common::shmem_pool>(shmkey, shm_size);
    if (!pool) {
        LOG(FATAL) << "GrpcServerThread: Failed allocating pool!";
        return false;
    }
    if (!pool->attach()) {
        LOG(FATAL) << "GrpcServerThread: Failed attaching to shmem";
        return false;
    }

    auto &flow_context = m_flows[flow_id];

    flow_context.pool = pool;
    for (auto next_stage_id : stage.next_stage())
        flow_context.next_stages.emplace(next_stage_id);

    return true;
}

void GrpcServerThread::reset_stats()
{
    m_sent_bytes = m_dropped_bytes = 0;
    m_sent_frames = 0;
    m_time_spent_decoding_usec = 0;
}

bool GrpcServerThread::handle_subscribe(imif::messages::msl::SubscriptionRequest &subcription_request, subscriber *sub)
{
    auto flow_it = m_flows.find(subcription_request.flow_id());
    if (flow_it == m_flows.end()) {
        return false; // not a grpc flow
    }
    if (!m_result_thread) {
        m_result_thread = std::make_shared<result_thread>(m_broker_uds_path);
        if (!m_result_thread->start()) {
            LOG(ERROR) << "unable to start result thread!";
        }
    }
    return m_result_thread->handle_subscribe(subcription_request.flow_id(), subcription_request.stage_id(), sub);
}

bool GrpcServerThread::handle_unsubscribe(imif::messages::msl::SubscriptionRequest &subcription_request, subscriber *sub)
{
    if (m_result_thread) {
        return m_result_thread->handle_unsubscribe(subcription_request.flow_id(), subcription_request.stage_id(), sub);
    }
    return false;
}

bool GrpcServerThread::register_listener(uint32_t listener_id, listen_call_data *call_data)
{
    if (m_listener_map.find(listener_id) == m_listener_map.end()) {
        m_listener_map.insert(std::make_pair(listener_id, call_data));
        return true;
    } else {
        LOG(ERROR) << "Tried to register listener with an ID already in use: " << listener_id;
        return false;
    }
}

void GrpcServerThread::remove_listener(uint32_t listener_id) { m_listener_map.erase(listener_id); }

imif::messages::msl::ChunkResponseOptions GrpcServerThread::send_chunk(const std::string &content, uint32_t flow_id)
{
    auto it = m_flows.find(flow_id);
    if (it == m_flows.end()) {
        LOG(ERROR) << "flow id: " << flow_id << " not recognized";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_FAIL;
    }
    auto &flow_context = it->second;
    auto pool = flow_context.pool;
    if (!pool) {
        LOG(FATAL) << "Shared memory pool is missing.";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_FAIL;
    }
    if (content.size() == 0) {
        LOG(ERROR) << "Got content with size 0. Treat it as successful send";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_SUCCESS;
    }

    if (pool->get_consecutive_free() < content.size()) {
        LOG(INFO) << "Not enought space in shmem!";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_BUSY;
    }
    
    std::shared_ptr<common::shmem_buff> write_ptr = pool->alloc_buff(content.size());
    if (!write_ptr) {
        LOG(FATAL) << "failed allocating buffer";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_FAIL;
    }
    std::copy_n(content.c_str(), content.size(), write_ptr->ptr());

    messages::mstream::EventBsReady event;
    event.set_supports_backpressure(true);
    event.set_source_id(flow_id);
    event.mutable_buff()->CopyFrom(*write_ptr);
    auto flow = event.add_flow();

    flow->set_id(flow_id);
    bool next_stages_exist = false;
    for (auto stage_id : flow_context.next_stages) {
        flow->add_stage_id(stage_id);
        next_stages_exist = true;
    }

    LOG(DEBUG) << "Sending event INPUT_BS_READY";
    if (next_stages_exist && !common::broker_thread::send_msg(m_broker_socket, messages::enums::INPUT_BS_READY, event)) {
        LOG(ERROR) << "Failed sending INPUT_BS_READY";
        return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_BUSY;
    }
    add_sent_bytes(content.size());
    return messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_SUCCESS;
}

bool infer_call_data::get_image_dimensions(const std::string &img_data, int &height, int &width)
{
    if (img_data.length() < 4)
        return false;
    auto imgdata = reinterpret_cast<const unsigned uint8_t *>(img_data.c_str());

    size_t segment_start_idx = 0;
    while (segment_start_idx + 8 < img_data.length()) {
        if (imgdata[segment_start_idx] != 0xFF)
            return false;
        if (imgdata[segment_start_idx + 1] >= 0xD0 && imgdata[segment_start_idx + 1] <= 0xD9) { // SOI, RSTn, EOI
            segment_start_idx += 2;
        } else if (imgdata[segment_start_idx + 1] == 0xC0) { // SOF0
            height = (imgdata[segment_start_idx + 5] << 8) + imgdata[segment_start_idx + 6];
            width = (imgdata[segment_start_idx + 7] << 8) + imgdata[segment_start_idx + 8];
            return true;
        } else {
            segment_start_idx += 2 + (imgdata[segment_start_idx + 2] << 8) + imgdata[segment_start_idx + 3];
        }
    }
    return false;
}

subscribe_call_data::subscribe_call_data(GrpcServerThread *this_thread) : m_responder(&m_ctx), m_thread(this_thread)
{
    s_service->RequestSubscribe(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void subscribe_call_data::process(GrpcServerThread *grpc_thread)
{
    if (m_status == PROCESS) {
        new subscribe_call_data(m_thread);
        listen_call_data *listener = (listen_call_data *)m_thread->listener_by_id(m_command.client_id());
        if (listener == nullptr) {
            LOG(ERROR) << "Asked to subscribe to an unregistered client_id";
            m_output.set_success(false);
        } else {
            if (m_command.subscribe()) {
                m_output.set_success(grpc_thread->handle_subscribe(m_command, listener));
            } else {
                m_output.set_success(grpc_thread->handle_unsubscribe(m_command, listener));
            }
        }
        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

listen_call_data::listen_call_data(GrpcServerThread *server) : m_responder(&m_ctx), m_thread(server)
{
    s_service->RequestListen(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
    m_status = INIT;
}

void listen_call_data::process(GrpcServerThread *grpc_thread)
{
    if (m_status == INIT) {
        new listen_call_data(m_thread);
        m_id = m_command.client_id();

        if (!m_thread->register_listener(m_id, this)) {
            LOG(ERROR) << "Failed to register listener";
            deallocate();
            return;
        }
        m_status = READY;
    } else if (m_status == PROCESS) {
        m_publishing_mutex.lock();
        m_status = READY;
        if (!m_outstanding_events.empty()) {
            auto flow_id = std::get<0>(m_outstanding_events.front());
            auto msg = std::get<1>(m_outstanding_events.front());
            publish_event_safe(flow_id, msg);
            m_outstanding_events.pop();
        }
        m_publishing_mutex.unlock();
    } else if (m_status == FINISH) {
        // unsubscribe from all flows
        m_thread->remove_listener(m_id);
        deallocate();
    } // if m_status is READY, do nothing.
}

void listen_call_data::publish_event_safe(uint32_t flow_id, const messages::types::ResultReady &message)
{
    if (m_status == READY) {
        m_status = PROCESS;
        imif::messages::msl::Event output;
        output.set_flow_id(flow_id);
        output.mutable_message()->CopyFrom(message);
        m_responder.Write(output, this);
    } else {
        m_outstanding_events.emplace(std::make_pair(flow_id, message));
    }
}

void listen_call_data::publish_event(uint32_t flow_id, const messages::types::ResultReady &message)
{
    m_publishing_mutex.lock();
    publish_event_safe(flow_id, message);
    m_publishing_mutex.unlock();
}

void listen_call_data::stop_listening() { m_status = FINISH; }

listen_call_data *GrpcServerThread::listener_by_id(uint32_t client_id)
{
    auto it = m_listener_map.find(client_id);
    if (it == m_listener_map.end()) {
        return nullptr;
    }
    return it->second;
}
