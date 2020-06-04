
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

#include "mstream_rtsp_thread.h"
#include "common_os_utils.h"
#include "common_string_utils.h"

#include <messages/proto/mgmt.pb.h>

#define SHMEM_BUFF_SIZE 128 * 1024

using namespace imif;
using namespace common;
using namespace mstream;

mstream_rtsp_thread::mstream_rtsp_thread(const std::string broker_uds)
    : thread_base(), m_module_name("mstream"), m_broker_uds(broker_uds)
{
    m_current_map.clear();
    m_configs.clear();
    m_pool_map.clear();
    m_flow_stages.clear();
    m_rtsp_clients.clear();
    m_source_flows.clear();
    m_flow_source.clear();
}

mstream_rtsp_thread::~mstream_rtsp_thread() { LOG(TRACE) << "mstream_rtsp_thread::~mstream_rtsp_thread()"; }

void mstream_rtsp_thread::on_thread_stop()
{
    LOG(TRACE) << "mstream_rtsp_thread::on_thread_stop()";
    reset();

    should_stop = true;
}

void mstream_rtsp_thread::reset()
{
    m_current_map.clear();
    m_pool_map.clear();
    m_broker_socket.reset();
    m_drop_buff = nullptr;

    if (m_rtsp_util_thread.is_running()) {
        // push event to utility thread to wake it up
        m_rtsp_util_thread.push_event(eMstEvents::STOP_THREAD, nullptr);
        m_rtsp_util_thread.stop();
    }
}

bool mstream_rtsp_thread::init()
{
    LOG(TRACE) << "mstream_rtsp_thread::init()";
    m_broker_socket = std::make_shared<common::SocketClient>(m_broker_uds);
    if (!m_broker_socket) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds;
        return false;
    }
    const auto error_msg = m_broker_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds << " [ERROR: " << error_msg << "]";
        m_broker_socket.reset();
        return false;
    }
    m_drop_buff = std::shared_ptr<uint8_t>(new uint8_t[SHMEM_BUFF_SIZE], [](uint8_t *obj) {
        if (obj)
            delete[] obj;
    });

    if (!m_drop_buff) {
        LOG(ERROR) << "Failed allocating buffer for dropped frames!";
        return false;
    }
    if (!m_rtsp_util_thread.start()) {
        LOG(ERROR) << "Failed starting utility thread";
        return false;
    }

    LOG(DEBUG) << "mstream_rtsp_thread::init successful";
    return true;
}

bool mstream_rtsp_thread::get_playing_source(uint32_t source_id)
{
    auto client_it = m_rtsp_clients.find(source_id);
    if (client_it != m_rtsp_clients.end()) {
        return client_it->second->getPlaying();
    }

    return false;
}

bool mstream_rtsp_thread::add_source(const messages::types::Source &source)
{
    uint32_t source_id = source.id();
    LOG(TRACE) << "rtsp thread: adding source: " << source_id;

    if (source.type() != messages::enums::StreamType::RTSP) {
        LOG(WARNING) << "Got a source not rtsp, ignoring";
        return false;
    }

    auto &src = source.input();
    if (src.find("rtsp") == std::string::npos) {
        LOG(ERROR) << "Invalid url: " << src;
        LOG(ERROR) << "Failed adding source: " << source;
        return false;
    }
    uint32_t id = source.id();
    LOG(DEBUG) << "addClient(), uri=" << src << " id=" << int(id);
    auto client = std::make_shared<RtspClientInst>(id, src, m_dump_path);
    if (!client) {
        LOG(ERROR) << "Failed allocating client with id=" << id << " uri=" << src;
        return false;
    }

    if (!create_shared_buff(source_id)) {
        LOG(ERROR) << "Failed creating shared_buff for source " << source_id;
        return false;
    }

    m_rtsp_clients[source_id] = client;
    m_rtsp_util_thread.push_event(eMstEvents::SETUP_STREAM, client);
    return true;
}

bool mstream_rtsp_thread::start_source(uint32_t source_id)
{
    LOG(TRACE) << "rtsp thread: starting source: " << source_id;
    auto client_it = m_rtsp_clients.find(source_id);
    if (client_it == m_rtsp_clients.end()) {
        LOG(ERROR) << "Unknown source" << source_id;
        return false;
    }
    m_rtsp_util_thread.push_event(eMstEvents::START_STREAM, client_it->second);
    if (!m_enabled) {
        return true;
    }
    // Start streaming ...
    LOG(INFO) << "Start RTSP stream " << source_id << " RX and forwared to MDECODE...";
    m_rtsp_util_thread.push_event(eMstEvents::PLAY_STREAM, client_it->second);
    return true;
}

bool mstream_rtsp_thread::remove_source(uint32_t source_id)
{
    LOG(TRACE) << "rtsp thread: removing source: " << source_id;
    auto client_it = m_rtsp_clients.find(source_id);
    if (client_it == m_rtsp_clients.end()) {
        LOG(ERROR) << "Unknown source" << source_id;
        return false;
    }
    m_rtsp_util_thread.push_event(eMstEvents::TEAR_DOWN_STREAM, client_it->second);
    m_rtsp_clients.erase(source_id);
    m_source_flows.erase(source_id);
    m_pool_map.erase(source_id); // frees memory
    return true;
}

bool mstream_rtsp_thread::add_flow(const messages::types::Flow &flow)
{
    auto source_id = flow.source_id();
    auto flow_id = flow.id();
    LOG(TRACE) << "Adding flow: " << flow_id << " for source: " << source_id;
    m_flow_source[flow_id] = source_id;
    m_source_flows[source_id].push_back(flow_id);

    uint32_t stages =
        std::count_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });
    if (stages > 1) {
        LOG(ERROR) << "Invalid flow configuration - NET participate more then once";
        return false;
    } else if (stages == 0) {
        LOG(DEBUG) << "NET does not participate in this flow " << flow_id;
        return true;
    }

    auto stage_it =
        std::find_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });

    auto &stage = *stage_it;

    m_flow_stages[flow_id].CopyFrom(stage);

    return true;
}

bool mstream_rtsp_thread::remove_flow(uint32_t flow_id)
{
    LOG(TRACE) << "rtsp thread: removing flow: " << flow_id;
    auto flow_source_it = m_flow_source.find(flow_id);
    if (flow_source_it == m_flow_source.end()) {
        LOG(ERROR) << "flow not found: " << flow_id;
        return false;
    }
    auto source_id = flow_source_it->second;
    m_flow_source.erase(flow_source_it);
    m_source_flows[source_id].remove(flow_id);
    m_flow_stages.erase(flow_id);
    return true;
}

void mstream_rtsp_thread::push_event(messages::enums::Opcode opcode, const google::protobuf::Message &msg)
{
    m_event_queue.push_event(opcode, msg);
}

bool mstream_rtsp_thread::work()
{
    usleep(1000); // 1 millisecond
    auto event = m_event_queue.pop_event();
    if (event) {
        handle_msg(messages::enums::Opcode(event->opcode), event->msg.get(), event->msg_len);
    }

    if (!m_enabled) {
        rtsp_keep_alive();
        return true;
    }

    if (!get_frame_from_rtsp()) {
        LOG(ERROR) << "Failed getting frame from rtsp!";
        return true;
    }
    return true;
}

bool mstream_rtsp_thread::handle_msg(messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
    case messages::enums::Opcode::MGMT_ADD_SOURCE: {
        messages::mgmt::AddSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing AddSource";
            return false;
        }
        if (!add_source(request.source())) {
            LOG(ERROR) << "RTSP thread failed to add source";
        }
    } break;
    case messages::enums::Opcode::MGMT_START_FLOW: {
        messages::mgmt::StartSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing StreamAdd";
            return false;
        }
        start_source(request.source_id());

    } break;
    case messages::enums::Opcode::MGMT_ADD_FLOW: {
        messages::mgmt::AddFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Flow";
            return false;
        }

        if (!add_flow(request.flow())) {
            LOG(ERROR) << "RTSP thread failed to add source";
        }
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_FLOW: {
        messages::mgmt::RemoveFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveFlow";
            return false;
        }
        LOG(INFO) << "MGMT_REMOVE_FLOW: " << request;

        if (!remove_flow(request.flow_id())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_GLOBAL_CONFIG: {
        messages::mgmt::GlobalConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing GlobalConfig";
            return false;
        }

        LOG(INFO) << "MGMT_GLOBAL_CONFIG: " << request;

        if (!global_config(request)) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_ENABLE: {
        messages::mgmt::Enable request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Enable";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "Recieved MGMT_ENABLE";

        if (m_enabled != request.enable()) {
            handle_enable(request.enable());
        }

        m_enabled = request.enable();
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_SOURCE: {
        messages::mgmt::RemoveSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveSource";
            return false;
        }
        LOG(INFO) << "MGMT_REMOVE_SOURCE: " << request;
        if (!remove_source(request.source_id())) {
            // Send erro to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_ADD_CONFIG: {
        messages::mgmt::AddConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing AddConfig";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "MGMT_ADD_CONFIG: " << request;

        if (!add_config(request.config())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_CONFIG: {
        messages::mgmt::RemoveConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveConfig";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "MGMT_REMOVE_CONFIG: " << request;
        auto config_id = request.config_id();

        if (!remove_config(config_id)) {
        }
    } break;
    case messages::enums::Opcode::MGMT_RESET: {
        messages::mgmt::ResetMod request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing reset request";
            return false;
        }
        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "Received MGMT_RESET";
        reset();
    } break;
    default: {
        LOG(ERROR) << "Unidentified opcode: " << opcode;
    } break;
    }
    return true;
}

void mstream_rtsp_thread::handle_enable(bool enable)
{
    if (enable) {
        LOG(TRACE) << "Handling enable";
        for (auto client : m_rtsp_clients) {
            LOG(INFO) << "Start RTSP stream " << client.first;
            m_rtsp_util_thread.push_event(eMstEvents::PLAY_STREAM, client.second);
        }
    } else {
        LOG(TRACE) << "Handling disable";
        for (auto client : m_rtsp_clients) {
            LOG(INFO) << "PAUSE RTSP stream " << client.first;
            m_rtsp_util_thread.push_event(eMstEvents::PAUSE_STREAM, client.second);
        }
    }
}

bool mstream_rtsp_thread::global_config(const messages::mgmt::GlobalConfig &global_config)
{
    if (!common::string_utils::caseless_eq(global_config.module_name(), m_module_name)) {
        // ignore configs that wasnt sent to me
        return true;
    }

    if (!global_config.dump_path().empty()) {
        m_dump_path = global_config.dump_path();
        LOG(INFO) << "received dump_path: " << m_dump_path;

        for (auto &rtspc_pair : m_rtsp_clients) {
            auto &rtsp_client = rtspc_pair.second;
            rtsp_client->openDumpFile(m_dump_path);
        }
    }

    return true;
}

bool mstream_rtsp_thread::add_config(const messages::types::Config &config)
{
    messages::mstream::Config mstConfig;
    if (!config.config().UnpackTo(&mstConfig)) {
        LOG(ERROR) << "Failed getting mstream config";
        return false;
    }

    m_configs[config.id()].CopyFrom(mstConfig);

    return true;
}

bool mstream_rtsp_thread::remove_config(uint32_t config_id)
{
    m_configs.erase(config_id);
    return true;
}

bool mstream_rtsp_thread::rtsp_keep_alive()
{
    for (auto &rtspc_pair : m_rtsp_clients) {
        auto &rtspc_prt = rtspc_pair.second;
        if (!rtspc_prt->getPlaying() && rtspc_prt->getSetup()) {
            // We already setup the stream with the server but we still don't started the stream
            // Prevent timeout on this stream
            rtspc_prt->sendKeepAlive();
            continue;
        }
    }

    return true;
}

bool mstream_rtsp_thread::get_frame_from_rtsp()
{
    for (auto &rtspc_pair : m_rtsp_clients) {
        auto &rtspc_prt = rtspc_pair.second;
        int source_id = rtspc_prt->getID();
        if (!rtspc_prt->getPlaying()) {
            LOG(DEBUG) << "source_id " << source_id << " Not playing";
            if (rtspc_prt->getSetup()) {
                // We already setup the stream with the server but we still haven't started the stream
                // Prevent timeout on this stream
                rtspc_prt->sendKeepAlive();
            }
            continue;
        }

        auto elem = m_current_map.find(source_id);
        if (elem == m_current_map.end()) {
            LOG(ERROR) << "Unexpeced source_id=" << source_id;
            continue;
        }

        auto &current_buff = elem->second.buff;
        auto &written_size = elem->second.buff_written;
        auto &frame_boundary_size = elem->second.buff_frame_boundary;
        auto &frame_sizes = elem->second.frame_sizes;

        if (!current_buff) {
            if (m_pool_map[source_id]->get_consecutive_free() < SHMEM_BUFF_SIZE) {
                LOG(INFO) << "There is not enough space to allocate more buff for source " << source_id;
                drop_frame(rtspc_prt);
                continue;
            }
            // allocate new buff
            current_buff = m_pool_map[source_id]->alloc_buff(SHMEM_BUFF_SIZE);
            if (!current_buff) {
                LOG(ERROR) << "Failed allocating new buff source " << source_id;
                drop_frame(rtspc_prt);
                continue;
            }
            written_size = 0;
        }

        if (m_source_flows[source_id].empty()) {
            LOG(DEBUG) << "Dropping frame as there's no flow for this source:" << source_id;
            drop_frame(rtspc_prt);
            continue;
        }

        auto current_buff_size = current_buff->buff_size();
        uint8_t *ret_ptr = nullptr;
        size_t data_size = 0;

        bool stop_loop = false;
        bool send_data = false;
        do {
            if (!rtspc_prt->getSynced()) {
                if (!drop_frame(rtspc_prt)) {
                    break;
                }
            }
            size_t buff_size = current_buff_size - written_size;
            uint8_t *buf_data = current_buff->ptr() + written_size;
            ret_ptr = rtspc_prt->getMediaData("video", buf_data, &data_size, buff_size);
            if (!ret_ptr && written_size != 0) {
                // LOG(DEBUG) << "ID " << source_id << " No media";
                stop_loop = true;
                break;
            } else if (ret_ptr && ret_ptr != buf_data) {
                size_t framse_size = ret_ptr - current_buff->ptr() - frame_boundary_size;
                frame_sizes.push_back(framse_size);
                frame_boundary_size = ret_ptr - current_buff->ptr();
            }

            written_size += data_size;

            if (ret_ptr && data_size == 0 && frame_boundary_size == 0) {
                // There is no more space in the buffer for more media
                // but we don't have a full frame yet - try to resize the buffer
                if (!current_buff->reallocate(current_buff_size * 2)) {
                    LOG(ERROR) << "ID " << source_id << " Failed to resize buff";
                    current_buff->drop();
                    current_buff = nullptr;
                    if (written_size != 0) {
                        rtspc_prt->setSynced(false);
                    }
                    written_size = 0;
                    stop_loop = true;
                } else {
                    current_buff_size = current_buff->buff_size();
                }
            } else if (written_size * 2 < current_buff_size || frame_boundary_size == 0) {
                // wait for more data to come
                continue;
            } else if (written_size > current_buff_size) {
                // Buffer overflow!!!
                LOG(ERROR) << "ID " << source_id << " Written " << written_size << " buffer_size=" << current_buff_size
                           << ". Buffer overflow";
                current_buff = nullptr;
                return false;
            } else {
                send_data = true;
                stop_loop = true;
            }
        } while (!stop_loop);

        if (!send_data)
            continue;

        current_buff->set_used_size(frame_boundary_size);

        __sync_add_and_fetch(&m_sent_bytes, frame_boundary_size);

        size_t file_wr_size = 0;
        if (rtspc_prt->isDumping()) {
            file_wr_size = rtspc_prt->writeToDumpFile((uint8_t *)current_buff->ptr(),
                                                      frame_boundary_size); // will do nothing if file is not open //
            if (file_wr_size != frame_boundary_size) {
                LOG(ERROR) << "rtspc_prt->writeToDumpFile() --> file_wr_size != frame_boundary_size";
            }
        }

        written_size = written_size - frame_boundary_size;

        messages::mstream::EventBsReady frame_ready;
        frame_ready.set_source_id(source_id);
        frame_ready.set_supports_backpressure(false);

        if (written_size != 0) {
            frame_ready.mutable_buff()->CopyFrom(current_buff->split(frame_boundary_size));
        } else {
            frame_ready.mutable_buff()->CopyFrom(*current_buff);
        }

        bool next_stages_exist = false;
        auto &stream_flows = m_source_flows[source_id];
        for (auto flow_id : stream_flows) {
            auto flow_event = frame_ready.add_flow();
            flow_event->set_id(flow_id);
            auto &stage = m_flow_stages[flow_id];
            for (auto next_stage : stage.next_stage()) {
                flow_event->add_stage_id(next_stage);
                next_stages_exist = true;
            }
        }

        for (auto elem : frame_sizes) {
            frame_ready.add_frame_sizes(elem);
        }

        frame_sizes.clear();
        frame_boundary_size = 0;
        // try to resize
        if (written_size != 0) {
            if (!current_buff->reallocate(SHMEM_BUFF_SIZE)) {
                LOG(ERROR) << "ID " << source_id << " Failed to resize buff, Setting as not synced!";
                current_buff->drop();
                rtspc_prt->setSynced(false);
                current_buff = nullptr;
                written_size = 0;
            }
        } else {
            current_buff = nullptr;
        }

        if (!next_stages_exist) {
            continue;
        }

        LOG(DEBUG) << "Sending INPUT_BS_READY";
        if (!broker_thread::send_msg(m_broker_socket, messages::enums::INPUT_BS_READY, frame_ready)) {
            LOG(ERROR) << "Failed sending INPUT_BS_READY";
            __sync_add_and_fetch(&m_dropped_bytes, written_size);
            written_size = 0;
            continue;
        }
    }
    return true;
}
bool mstream_rtsp_thread::drop_frame(std::shared_ptr<RtspClientInst> rtspc_prt)
{
    size_t data_size = 0;
    uint8_t *ret_ptr;
    ret_ptr = rtspc_prt->getMediaData("video", m_drop_buff.get(), &data_size, SHMEM_BUFF_SIZE);
    if (!ret_ptr) {
        LOG(INFO) << "No media ";
        return false;
    } else if (ret_ptr != m_drop_buff.get()) {
        // we drop a full frame!
        rtspc_prt->setSynced(true);
    } else {
        rtspc_prt->setSynced(false);
    }

    if (ret_ptr && !m_dump_path.empty()) {
        size_t file_wr_size = 0;
        file_wr_size =
            rtspc_prt->writeToDumpFile((uint8_t *)m_drop_buff.get(), data_size); // will do nothing if file is not open //
        if (file_wr_size != data_size) {
            LOG(ERROR) << "rtspc_prt->writeToDumpFile() --> file_wr_size != data_size";
        }
    }

    __sync_add_and_fetch(&m_dropped_bytes, data_size);
    return true;
}

bool mstream_rtsp_thread::create_shared_buff(uint32_t source_id)
{
    if (m_pool_map.find(source_id) != m_pool_map.end()) {
        LOG(ERROR) << "Can't create shmem for source_id " << source_id << ". Already exist!";
        return false;
    }
    // Create shared memory
    int pid = common::os_utils::get_pid();
    int shmkey = (pid << 8) | source_id;
    size_t shm_size = 5 * 1024 * 1024; // 5MB
    auto pool = std::make_shared<imif::common::shmem_pool>(shmkey, shm_size);
    if (!pool) {
        LOG(FATAL) << "MstThread: Failed allocating pool!";
        should_stop = true;
        return false;
    }
    if (!pool->attach()) {
        LOG(FATAL) << "MstThread: Failed attaching to shmem";
        should_stop = true;
        return false;
    }

    m_pool_map[source_id] = pool;
    m_current_map.insert({source_id, current_buff()});
    return true;
}
