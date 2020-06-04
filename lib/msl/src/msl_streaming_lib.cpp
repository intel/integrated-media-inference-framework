
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

#include "../include/msl_streaming_lib.h"

#include <grpcpp/grpcpp.h>

#include "easylogging++.h"

#include <thread>
#include <unistd.h>

namespace imif {
namespace mstream {

streaming_client::streaming_client() {}

streaming_client::~streaming_client() { disconnect(); }

bool streaming_client::connect(std::string &host_or_ip_str, std::string port_str)
{
    if (m_channel) {
        disconnect();
    }
    std::string connection_string;
    connection_string.append(host_or_ip_str);
    connection_string.append(":");
    if (port_str.empty()) {
        connection_string.append(std::to_string(default_port));
    } else {
        connection_string.append(port_str);
    }
    LOG(INFO) << "Connecting to: " << connection_string;
    grpc::ChannelArguments ch_args;
    ch_args.SetMaxReceiveMessageSize(max_message_size);
    m_channel = grpc::CreateCustomChannel(connection_string, grpc::InsecureChannelCredentials(), ch_args);
    m_stub = imif::services::msl::StreamingLibrary::NewStub(m_channel);

    if (!m_stub) {
        LOG(ERROR) << "Failed to create channel.";
        return false;
    }
    if (!is_connected()) {
        LOG(ERROR) << "Connection failed";
        return false;
    }

    return connect_to_server();
}

void streaming_client::disconnect()
{
    LOG(TRACE) << "Disconnecting...";

    stop_listen();
    m_stub.reset();
    m_channel.reset();
}

bool streaming_client::is_connected()
{
    if (!m_stub) {
        LOG(ERROR) << "GRPC Not connected";
        return false;
    }

    imif::messages::msl::PingRequest ping_req;
    imif::messages::msl::PingResponse ping_rsp;
    grpc::ClientContext context;

    grpc::Status status = m_stub->Ping(&context, ping_req, &ping_rsp);
    return check_error(status);
}

bool streaming_client::connect_to_server()
{
    if (!m_stub) {
        LOG(ERROR) << "GRPC Not connected";
        return false;
    }

    imif::messages::msl::ConnectRequest connect_req;
    imif::messages::msl::ConnectResponse connect_rsp;
    grpc::ClientContext context;

    grpc::Status status = m_stub->Connect(&context, connect_req, &connect_rsp);
    if (!check_error(status))
        return 0;

    m_client_id = connect_rsp.client_id();

    return true;
}

uint32_t streaming_client::get_client_id() { return m_client_id; }

bool streaming_client::infer(const uint32_t flow_id, const imif::messages::enums::FrameFormat frame_format,
                             const imif::messages::types::FramesData &frames_data, imif::messages::msl::InferResponse &response)
{
    if (!m_stub) {
        LOG(ERROR) << "GRPC Not connected";
        return false;
    }

    grpc::ClientContext context;
    imif::messages::msl::InferRequest infer_request;

    infer_request.set_flow_id(flow_id);
    infer_request.set_frame_format(frame_format);
    infer_request.mutable_frames_data()->CopyFrom(frames_data);

    grpc::Status status = m_stub->Infer(&context, infer_request, &response);

    return check_error(status);
}

bool streaming_client::check_error(grpc::Status &status)
{
    if (!status.ok()) {
        LOG(ERROR) << "RPC failed: " << status.error_message();
        LOG(ERROR) << "Details: " << status.error_details();
        return false;
    }
    return true;
}
bool streaming_client::subscribe(uint32_t flow_id, uint32_t stage_id, bool subscribe)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    if (!m_listener_thread_running) {
        LOG(DEBUG) << "Starting listener thread";
        if (!listen()) {
            m_stub = nullptr;
            m_channel = nullptr;
            return false;
        }
    }

    imif::messages::msl::SubscriptionRequest subscriptionRequest;

    subscriptionRequest.set_client_id(m_client_id);
    subscriptionRequest.set_subscribe(subscribe);
    subscriptionRequest.set_flow_id(flow_id);
    subscriptionRequest.set_stage_id(stage_id);

    imif::messages::msl::SubscriptionResponse subscriptionResponse;

    grpc::ClientContext context;
    grpc::Status status = m_stub->Subscribe(&context, subscriptionRequest, &subscriptionResponse);
    if (!check_error(status)) {
        return false;
    }
    if (!subscriptionResponse.success()) {
        LOG(ERROR) << "Subscription refused by server.";
        return false;
    }
    return true;
}

bool streaming_client::listen()
{
    m_listener_context = std::make_shared<grpc::ClientContext>();
    if (!m_listener_context) {
        LOG(ERROR) << "Failed to create ClientContext!";
        return false;
    }
    m_listener_cq = std::make_shared<grpc::CompletionQueue>();
    if (!m_listener_cq) {
        m_listener_context = nullptr;
        LOG(ERROR) << "Failed to create cq!";
        return false;
    }
    // open the event source:
    imif::messages::msl::ClientID clientID;
    clientID.set_client_id(m_client_id);

    m_event_reader = m_stub->AsyncListen(m_listener_context.get(), clientID, m_listener_cq.get(), this);
    if (!m_event_reader) {
        m_listener_cq = nullptr;
        m_listener_context = nullptr;
        LOG(ERROR) << "Failed to listen!";
        return false;
    }
    m_event_dispatch_thread = std::thread(&streaming_client::event_dispatch, this);
    return true;
}

void streaming_client::event_dispatch()
{
    imif::messages::msl::Event event;
    void *got_tag;
    bool ok = false;
    m_listener_thread_running.store(true);

    while (m_listener_thread_running.load()) {
        if (!m_listener_cq->Next(&got_tag, &ok)) {
            LOG(ERROR) << "Completion queue shutting down";
            break;
        }
        if (ok) {
            m_event_reader->Read(&event, got_tag);
            if (event.message().detected_object_size() != 0) {
                if (m_listener_callback) {
                    m_listener_callback(event);
                }
            }
        } else {
            LOG(INFO) << "Disconnected from server!";
            break;
        }
    }
    m_listener_thread_running.store(false);
}
void streaming_client::register_listener_callback(CallbackFunc callback) { m_listener_callback = callback; }

void streaming_client::stop_listen()
{
    m_listener_thread_running.store(false);
    if (m_listener_context) {
        m_listener_context->TryCancel(); // releases m_event_dispatch_thread from Next(), stopping it.
    }

    grpc::Status status;
    void *tag;
    if (m_event_reader) {
        m_event_reader->Finish(&status, &tag);
    }
    if (!status.ok()) {
        LOG(DEBUG) << "Finish when disconnecting returned status that is not ok! " << status.error_message();
    }
    if (m_listener_cq) {
        m_listener_cq->Shutdown();
        bool ok;
        while (m_listener_cq->Next(&tag, &ok)) {
        }
    }

    if (m_event_dispatch_thread.joinable()) {
        m_event_dispatch_thread.join();
    }
    if (m_listener_context) {
        m_listener_context.reset();
    }
    if (m_event_reader) {
        m_event_reader.release();
    }
}

bool streaming_client::start_stream_file(const std::string &filename, uint32_t flow_id, float max_mbps)
{
    const std::lock_guard<std::mutex> lock(m_streaming_thread_mutex);
    if (!m_stub) {
        LOG(ERROR) << "GRPC Not connected";
        return false;
    }
    if (m_streaming_threads.find(flow_id) != m_streaming_threads.end()) {
        LOG(INFO) << "Can't start stream, flow_id " << flow_id << " already in use.";
        return false;
    }
    m_thread_should_stop[flow_id] = false;
    m_streaming_threads[flow_id] = std::thread(&streaming_client::stream_file, this, filename, flow_id, max_mbps);
    m_streaming_threads[flow_id].detach();
    return true;
}

bool streaming_client::stop_stream_file(uint32_t flow_id)
{
    const std::lock_guard<std::mutex> lock(m_streaming_thread_mutex);
    if (!m_stub) {
        LOG(ERROR) << "GRPC Not connected";
        return false;
    }
    auto it = m_thread_should_stop.find(flow_id);
    if (it == m_thread_should_stop.end()) {
        LOG(INFO) << "Can't stop stream, flow_id " << flow_id << " not used.";
        return false;
    }
    it->second = true;
    auto it2 = m_streaming_threads.find(flow_id);
    if (it2 == m_streaming_threads.end()) {
        LOG(INFO) << "Can't stop stream, flow_id " << flow_id << " not used.";
        return false;
    }
    return true;
}

void streaming_client::remove_thread(uint32_t flow_id)
{
    m_streaming_thread_mutex.lock();
    m_streaming_threads.erase(flow_id);
    m_streaming_thread_mutex.unlock();
}
bool streaming_client::stream_file(const std::string &filename, uint32_t flow_id, float max_mbps)
{
    remove_thread_raii remove_thread_raii_instance(flow_id, this);
    char buffer[MAX_CHUNK_SIZE];
    size_t read_bytes = 0;

    std::shared_ptr<grpc::ClientContext> context = std::make_shared<grpc::ClientContext>();
    if (!context) {
        LOG(ERROR) << "Failed allocating context";
        return false;
    }

    imif::messages::msl::Chunk chunk;
    chunk.set_flow_id(flow_id);

    imif::messages::msl::ChunkResponse return_status;
    auto reader_writer = m_stub->StreamFile(context.get());
    if (!reader_writer) {
        LOG(ERROR) << "Failed creating stream!";
        return false;
    }
    auto prev_chunk_timestamp = std::chrono::steady_clock::now();

    int sleep_us = 0;
    if (max_mbps) {
        sleep_us = MAX_CHUNK_SIZE * 8 * 1000 * 1000 / 1024 / 1024 / max_mbps; // time to sleep between chunks, in microseconds
    }

    std::ifstream input_stream(filename, std::ios::binary);
    if (!input_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << filename << " !!\n";
        return false;
    }
    auto &should_stop = m_thread_should_stop[flow_id];
    while (!should_stop) {
        if (sleep_us) { //moderate the rate in which we send data
            auto time_since_last_chunk =
                std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - prev_chunk_timestamp)
                    .count();
            int sleep_period = (int)sleep_us - (int)time_since_last_chunk;

            std::this_thread::sleep_for(std::chrono::microseconds(std::max(0, sleep_period)));
        }

        auto oldpos = input_stream.tellg();
        input_stream.read(buffer, MAX_CHUNK_SIZE);
        read_bytes = input_stream.gcount();

        if (input_stream.eof()) {
            input_stream.clear();
            input_stream.seekg(input_stream.beg);
        }

        chunk.mutable_content()->clear();
        chunk.set_content(buffer, read_bytes);

        if (!reader_writer->Write(chunk)) {
            LOG(ERROR) << "Failed writing!!";
            break;
        }

        return_status.Clear();
        if (!reader_writer->Read(&return_status)) {
            LOG(ERROR) << "Failed Read flow id " << flow_id;
        }
        prev_chunk_timestamp = std::chrono::steady_clock::now();

        if (return_status.response() == messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_BUSY) {
            LOG(ERROR) << "Flow id " << flow_id <<  
                          " Module returned busy. Try to increase the mbps limit - sleeping for 500ms";
            input_stream.seekg(oldpos);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } else if (return_status.response() != messages::msl::ChunkResponseOptions::CHUNK_RESPONSE_SUCCESS) {
            LOG(INFO) << "Failed streaming file: " << filename;
            break;
        }
    }
    LOG(INFO) << "Stopped streaming file: " << filename << " flow id " << flow_id;
    input_stream.close();

    reader_writer->WritesDone();
    reader_writer->Finish();
    context->TryCancel(); // releases m_event_dispatch_thread from Next(), stopping it.

    context.reset();

    return true;
}

} // namespace mstream
} // namespace imif
