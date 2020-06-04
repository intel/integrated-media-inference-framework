
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

#include "common_defines.h"
#include "common_mem_manager.h"
#include "common_os_utils.h"
#include "common_string_utils.h"
#include "tcp_sender_thread.h"

#include <dlfcn.h>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <messages/header.h>
#include <messages/proto/enums.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/tcp_sender.pb.h>

using namespace imif;
using namespace common;
using namespace sender;
using namespace cv;

static std::string get_ip_addr(const std::string &subnet)
{
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmpAddrPtr = NULL;

    std::string ip_str;

    std::string subnet_prefix = subnet.substr(0, subnet.find_last_of(".") + 1);
    if (subnet_prefix.empty()) {
        LOG(ERROR) << "bad subnet " << subnet;
        return ip_str;
    }

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        // is a valid IP4 Address
        tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        char addressBuffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
        std::string tmp_ip(addressBuffer, INET_ADDRSTRLEN);
        auto res = std::mismatch(subnet_prefix.begin(), subnet_prefix.end(), tmp_ip.begin());
        if (res.first != subnet_prefix.end()) {
            continue;
        }

        ip_str = tmp_ip;
        break;
    }
    if (ifAddrStruct != NULL)
        freeifaddrs(ifAddrStruct);
    return ip_str;
}

tcp_sender_thread::tcp_sender_thread(const std::string broker_uds, imif::common::logging *pLogger)
    : broker_thread("TCP_SENDER_THREAD", broker_uds), m_module_name("tcp_sender"), m_pLogger(pLogger)
{
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_deleted_frames.clear();
    m_output_map.clear();
    m_flow2shmkey.clear();
    m_flow2stageid.clear();
}

tcp_sender_thread::~tcp_sender_thread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void tcp_sender_thread::reset()
{
    LOG(TRACE) << "reset()";

    m_ui_sd = nullptr;

    clearOutputMap();
    m_output_stream_flow_ids.clear();
    common::shmem_buff_factory::shmem_pool_map.clear();

    m_flow2shmkey.clear();

    m_enabled = false;
}

void tcp_sender_thread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    log_stats(true);
    should_stop = true;
    reset();
}

bool tcp_sender_thread::post_init()
{
    subscribe({messages::enums::Opcode::MGMT_ADD_FLOW, messages::enums::Opcode::MGMT_REMOVE_FLOW,
               messages::enums::Opcode::MGMT_ADD_CONFIG, messages::enums::Opcode::MGMT_REMOVE_CONFIG,
               messages::enums::Opcode::MGMT_GLOBAL_CONFIG, messages::enums::Opcode::MGMT_REGISTER_RESPONSE,
               messages::enums::Opcode::MGMT_ENABLE, messages::enums::Opcode::MGMT_RESET,
               messages::enums::Opcode::MGMT_SET_LOG_LEVEL, messages::enums::Opcode::INFERENCE_RESULTS_READY,
               messages::enums::Opcode::DECODED_FRAME_READY});

    m_rate_limiter.set_rate_limit(-1);

    return true;
}

bool tcp_sender_thread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
    case messages::enums::Opcode::MGMT_REGISTER_RESPONSE: {
        messages::mgmt::RegisterResponse response;
        if (!response.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RegisterResponse";
            return false;
        }

        if (!common::string_utils::caseless_eq(response.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "Recieved MGMT_REGISTER_RESPONSE";
        m_registered = true;
        m_module_id = response.module_id();

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

        m_enabled = request.enable();
        LOG(INFO) << "Received MGMT_ENABLE=" << m_enabled;

        if (m_enabled) {
            handle_enable();
        } else {
            handle_disable();
        }
    } break;
    case messages::enums::Opcode::MGMT_SET_LOG_LEVEL: {
        messages::mgmt::SetLogLevel request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing SetLogLevel request";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "received SET_LOG_LEVEL request: " << request;
        m_pLogger->set_log_level_state(eLogLevel(request.log_level()), request.new_state());
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
    case messages::enums::Opcode::MGMT_ADD_FLOW: {
        messages::mgmt::AddFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Flow";
            return false;
        }

        LOG(INFO) << "MGMT_ADD_FLOW: " << request;

        if (!add_flow(request.flow())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
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
        LOG(INFO) << "MGMT_ADD_COFIG: " << request;

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

        if (!remove_config(request.config_id())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::INFERENCE_RESULTS_READY: {
        messages::types::EventResultReady frame;
        if (!frame.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveConfig";
            return false;
        }

        storeOutput(frame);
    } break;
    case messages::enums::DECODED_FRAME_READY: {
        messages::types::EventFrameReady requests;
        if (!requests.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing EventFrameReady";
            return false;
        }

        // LOG(DEBUG) << "DECODED_FRAME_READY: " << frame;

        for (auto &frame : requests.efr()) {
            storeOutput(frame);
        }
    } break;

    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
        // return false;
    } break;
    }

    return true;
}

bool tcp_sender_thread::handle_msg(std::shared_ptr<Socket> sd)
{
    if (sd->getSocketFd() == m_tcp_server_socket->getSocketFd()) {
        socket_server_accept(m_tcp_server_socket);
    } else if (m_ui_sd && sd->getSocketFd() == m_ui_sd->getSocketFd()) {
        while (sd->getBytesReady()) {
            messages::sProtoHeader header;
            int ret = read_proto_message(sd, header, m_rx_buffer, sizeof(m_rx_buffer));
            if (ret < 0) {
                LOG(ERROR) << "Failed reading and/or parsing message!";
                return false;
            } else if (ret == 0) {
                return true;
            }

            switch (header.opcode) {
            case messages::tcp_sender::MSTREAM_OUT_START: {
                messages::tcp_sender::OutStreamStart start;
                if (!start.ParseFromArray(m_rx_buffer, header.length)) {
                    LOG(ERROR) << "Failed parsing ipp::Start";
                    return false;
                }
                if (start.output_width() > 0)
                    m_output_width = start.output_width();
                if (start.output_height() > 0)
                    m_output_height = start.output_height();
                if (start.output_fps() > 0)
                    m_output_fps = start.output_fps();

                m_output_stream_flow_ids.clear();
                for (int idx = 0; idx < start.flow_id_list_size(); idx++) {
                    uint32_t flow_id = start.flow_id_list(idx);
                    m_output_stream_flow_ids.push_back(flow_id);
                }

                if (start.output_fps()) {
                    m_rate_limiter.set_rate_limit(start.output_fps() * start.flow_id_list_size());
                    LOG(DEBUG) << "IPP output rate set to " << m_rate_limiter.get_rate_limit();
                }

            } break;
            case messages::tcp_sender::MSTREAM_OUT_STOP: {
                m_output_stream_flow_ids.clear();
            } break;

            default: {
                LOG(ERROR) << "Unknown opcode " << std::hex << int(header.opcode) << std::dec;
            } break;
            }
        }
    } else {
        LOG(ERROR) << "Unknown socket " << sd->getSocketFd();
    }

    return true;
}

void tcp_sender_thread::clearOutputMap()
{
    for (auto &elem : m_output_map) {
        auto it = elem.second.begin();
        while (it != elem.second.end()) {
            it = elem.second.erase(it);
        }
    }
    m_output_map.clear();
}

void tcp_sender_thread::forceCloseSocket(std::shared_ptr<Socket> sd)
{
    LOG(INFO) << "Force socket close!";
    sd->closeSocket();
    del_socket(sd);
    sd.reset();
}

bool tcp_sender_thread::socket_disconnected(std::shared_ptr<Socket> sd)
{
    if (!m_ui_sd) {
        LOG(ERROR) << "unknown socket fd=" << sd->getSocketFd();
    } else if (m_ui_sd->getSocketFd() == sd->getSocketFd()) {
        LOG(INFO) << "pb socket disconnected. fd=" << sd->getSocketFd();
        m_ui_sd = nullptr;
        clearOutputMap();
        m_output_stream_flow_ids.clear();
    }
    return true;
}

bool tcp_sender_thread::socket_error(std::shared_ptr<Socket> sd) { return socket_disconnected(sd); }

bool tcp_sender_thread::socket_connected(std::shared_ptr<common::Socket> sd)
{
    if (m_ui_sd) {
        LOG(WARNING) << "pb socket was already accepted fd=" << sd->getSocketFd() << " . continue with the new one";
        del_socket(m_ui_sd);
        m_ui_sd = nullptr;
        m_output_stream_flow_ids.clear();
        m_rate_limiter.set_rate_limit(-1);
    }

    if (m_enabled) {
        LOG(INFO) << "pb socket connected fd=" << sd->getSocketFd();
        m_ui_sd = sd;
        add_socket(sd, true);
    } else {
        LOG(ERROR) << "Module disabled, forceCloseSocket";
        forceCloseSocket(sd);
    }
    return true;
}

bool tcp_sender_thread::before_select()
{
    if (!m_registered) {
        auto now = std::chrono::steady_clock::now();
        if (now > m_next_register) {
            // Register to management
            messages::mgmt::RegisterRequest mgmt_register;
            mgmt_register.set_module_name(m_module_name);
            send_msg(messages::enums::MGMT_REGISTER_REQUEST, mgmt_register);
            LOG(DEBUG) << "Sent register request";

            m_next_register = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        }
    }
    if (!m_enabled) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    if (now > m_next_frame_rate_update) {
        //update skip ratio, if required.
        m_rate_limiter.update_skip_ratio();
        m_next_frame_rate_update = now + std::chrono::milliseconds(FRAME_RATE_INTRVAL_MSEC);
    }

    log_stats();
    periodic_cleanup();

    return true;
}

void tcp_sender_thread::log_stats(bool force)
{

    auto time_since_last =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_stats).count();

    auto time_since_start =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_start_time).count();

    if (time_since_last < REPORT_INTRVAL_MSEC && !force) {
        return;
    }

    std::stringstream statistic_stream;
    double time_since_last_sec = time_since_last / 1000;

    statistic_stream << "\n-------------\n";
    statistic_stream << "Received video: " << m_incoming_frame_total / time_since_last_sec << " FPS ("
                     << (double)m_incoming_frame_bytes * 8 / 1024 / 1024 * 1000 / time_since_last << " Mbps)\n";
    statistic_stream << "Received inference results: " << m_incoming_inference_total / time_since_last_sec << " FPS\n";
    statistic_stream << "Skipped frames: " << m_skipped_frames / time_since_last_sec << " FPS (" << m_skipped_frames << ")\n";
    statistic_stream << "Sent frames: " << std::setw(4) << m_sent_frames / time_since_last_sec << " FPS/"
                     << m_sent_frames + m_skipped_frames << " (" << (double)m_sent_bytes * 8 / 1024 / 1024 * 1000 / time_since_last
                     << " Mbps)\n";
    statistic_stream << "Dropped frames: " << m_dropped_frames / time_since_last_sec << " FPS (" << m_dropped_frames << ")\n";

    statistic_stream << "Total run is " << std::setw(6) << (double)time_since_start / 1000 << " seconds" << std::endl;

    LOG(INFO) << statistic_stream.str();

    messages::mgmt::Statistics statistic;
    statistic.set_topic(m_module_name);
    statistic.set_stat(statistic_stream.str());
    send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);

    m_incoming_frame_total = m_incoming_frame_bytes = 0;
    m_incoming_inference_total = 0;
    m_sent_bytes = m_sent_frames = m_skipped_frames = 0;
    m_dropped_frames = 0;

    m_last_stats = std::chrono::steady_clock::now();
}

void tcp_sender_thread::periodic_cleanup()
{
    auto time_since_last =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_cleanup).count();

    if (time_since_last < CLEANUP_INTRVAL_MSEC) {
        return;
    }

    // cleanup stale entries
    for (auto &out_map_p : m_output_map) {
        auto &out_map = out_map_p.second;
        auto flow_id = out_map_p.first;

        auto last_result = m_last_inference_result[flow_id];                
        time_since_last = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - last_result).count();
        if (time_since_last < INFERENCE_STALL_INTERVAL_MSEC) {
            continue;
        }

        auto it = out_map.begin();
        while (it != out_map.end()) {
            if (it->second.frame_valid && it->second.result_valid) {
                sendOutput(flow_id);
                break;
            }
            auto frame_number = it->first;
            auto age =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - it->second.timestamp)
                    .count();
            if (age > AGING_INTERVAL_MSEC) {
                LOG(WARNING) << "Deleted flow " << flow_id << " frame " << frame_number
                             << " result_valid=" << it->second.result_valid << " frame_valid=" << it->second.frame_valid
                             << " age=" << age;
                m_deleted_frames[flow_id][frame_number] = it->second.timestamp;
                it = out_map.erase(it);
                m_dropped_frames++;
            } else {
                ++it;
            }
        }
    }
    m_last_cleanup = std::chrono::steady_clock::now();
}

bool tcp_sender_thread::is_known_flow(const messages::types::FlowEvent &flow)
{
    uint32_t flow_id = flow.id();
    auto stage_it = m_flow2stageid.find(flow_id);
    if (stage_it == m_flow2stageid.end()) {
        return false;
    }

    bool valid_stage = false;
    for (auto stage_id : flow.stage_id()) {
        if (stage_it->second == stage_id) {
            valid_stage = true;
            break;
        }
    }

    return valid_stage;
}

void tcp_sender_thread::storeOutput(messages::types::EventResultReady &output)
{
    m_incoming_inference_total += output.results_size();
    for (auto &result : output.results()) {
        if (!is_known_flow(result.frame_info().flow())) {
            continue;
        }

        const uint32_t flow_id = result.frame_info().flow().id();
        const uint64_t frame_num = result.frame_info().frame().frame_num();

        LOG(DEBUG) << "incoming results from ilb: flow_id " << flow_id << ": frame_num " << frame_num;

        auto &deleted_flow_frames = m_deleted_frames[flow_id];
        auto it = deleted_flow_frames.find(frame_num);
        if (it != deleted_flow_frames.end()) {
            //Frame has been deleted, ignore inference data.
            auto delta =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - it->second).count();
            LOG(INFO) << "Also del flow " << flow_id << " frame " << frame_num << " result. delta=" << delta;
            deleted_flow_frames.erase(it);
            return;
        }

        if (!m_enabled) {
            return;
        }

        auto &flow_map = m_output_map[flow_id];
        auto &map_entry = flow_map[frame_num];
        if (map_entry.result.detected_object_size() == 0) {
            map_entry.result.set_frame_size(result.frame_size());
            map_entry.result.mutable_frame_info()->CopyFrom(result.frame_info());
        }
        for (auto &obj : result.detected_object()) {
            auto new_detected_object = map_entry.result.add_detected_object();
            new_detected_object->CopyFrom(obj);
            if (result.frame_info().frame().source_box().width() != 0 || result.frame_info().frame().source_box().height() != 0) {
                new_detected_object->mutable_box()->CopyFrom(result.frame_info().frame().source_box());
            }
        }
        map_entry.timestamp = std::chrono::steady_clock::now();

        if (++map_entry.subframe_number >= result.frame_info().frame().sub_frames()) {
            map_entry.result_valid = true;
            sendOutput(flow_id);
        }
        m_last_inference_result[flow_id] = std::chrono::steady_clock::now();
    }
}

void tcp_sender_thread::storeOutput(const messages::types::FrameReady &frame_ready)
{
    if (!is_known_flow(frame_ready.frame_info().flow())) {
        return;
    }

    m_incoming_frame_bytes += frame_ready.buff().buff_size();
    m_incoming_frame_total++;

    const uint64_t frame_num = frame_ready.frame_info().frame().frame_num();
    auto flow_id = frame_ready.frame_info().flow().id();

    std::shared_ptr<common::shmem_buff> buff = common::shmem_buff_factory::get_buff(frame_ready.buff());
    if (!buff) {
        LOG(ERROR) << "Failed getting buff: " << frame_ready.buff() << "(flow " << flow_id << ":" << frame_num << ")";
        return;
    }

    m_flow2shmkey[flow_id].insert(buff->shmkey());

    auto &deleted_flow_frames = m_deleted_frames[flow_id];
    auto it = deleted_flow_frames.find(frame_num);
    if (it != deleted_flow_frames.end()) {
        //inference data has been deleted, ignore frame.
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - it->second).count();
        LOG(INFO) << "Also del flow " << flow_id << " frame " << frame_num << " frame. delta=" << delta;
        deleted_flow_frames.erase(it);
        return;
    }

    if (!buff->is_valid()) {
        LOG(DEBUG) << "Not synced with producer, drop...";
        return;
    }

    if (!m_enabled) {
        return;
    }

    auto &flow_map = m_output_map[flow_id];
    auto &map_entry = flow_map[frame_num];
    map_entry.frame_info = frame_ready.frame_info();
    map_entry.frame = buff;
    map_entry.frame_valid = true;
    map_entry.timestamp = std::chrono::steady_clock::now();

    LOG(DEBUG) << "incoming frame: flow id :" << flow_id << ", frame #" << frame_num << ", context "
               << frame_ready.frame_info().frame().client_context();

    sendOutput(flow_id);
}

void tcp_sender_thread::sendOutput(uint32_t flow_id)
{
    auto &output_map = m_output_map[flow_id];
    auto output_elem = output_map.begin();
    auto last_result = m_last_inference_result[flow_id];                
    while (output_elem != output_map.end()) {
        auto frame_num = output_elem->first;
        auto &output = output_elem->second;
        if (!output.frame_valid || !output.result_valid) {
            auto age =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - output.timestamp).count();
            auto time_since_infer = 
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - last_result).count();
            if (age > AGING_INTERVAL_MSEC && time_since_infer > INFERENCE_STALL_INTERVAL_MSEC) {
                LOG(WARNING) << "Deleted flow " << flow_id << " frame " << frame_num << " result_valid=" << output.result_valid
                             << " frame_valid=" << output.frame_valid << " age=" << age;
                m_deleted_frames[flow_id][frame_num] = output.timestamp;
                output_elem = output_map.erase(output_elem);
                m_dropped_frames++;
                continue;
            }

            break; // goto next flows
        }

        LOG(DEBUG) << "Ready to send: output.flow_id = " << flow_id << " frame_number=" << frame_num;
        if (std::find(m_output_stream_flow_ids.begin(), m_output_stream_flow_ids.end(), flow_id) ==
            m_output_stream_flow_ids.end()) {
            //check if this flow was enabled
            LOG(DEBUG) << "flow id " << flow_id << " isn't enabled - releasing frame " << std::to_string(frame_num);
        } else {
            size_t bytes_write_pending = m_ui_sd->getBytesWritePending();
            size_t buffer_size = m_ui_sd->getBufferLength();
            size_t message_size = sizeof(imif::messages::sProtoHeader) + output.result.ByteSizeLong() + output.result.frame_size();
            if (buffer_size < bytes_write_pending + message_size) {
                LOG(WARNING) << "Not enough space to send the msg! buffer_size=" << buffer_size
                             << " size=" << bytes_write_pending + message_size;
                break;
            }

            output.result.mutable_frame_info()->CopyFrom(output.frame_info);
            auto frame_format = output.result.frame_info().frame().format();
            if (frame_format == "i420") {
                resize_frame_i420(output.frame->ptr(), output.result, output.result.frame_info().frame().height(),
                                  output.result.frame_info().frame().width());
            } else if (frame_format == "nv12") {
                convert_and_resize_nv12_to_i420(output.frame->ptr(), output.result);
            } else if (frame_format == "bgra") {
                convert_and_resize_bgra_to_i420(output.frame->ptr(), output.result);
            } else if (frame_format == "rgb") {
                convert_and_resize_rgb_to_i420(output.frame->ptr(), output.result);
            } else {
                LOG(WARNING) << "Unknown frame type " << frame_format << " may not be recognized by clients";
                output_elem = output_map.erase(output_elem);
                continue;
            }

            uint8_t *frame_ptr = m_resize_out_buff.get();

            output.frame->free();

            LOG(DEBUG) << "Send frame " << frame_num << " from flow " << flow_id << " to tcp socket";

            m_rate_limiter.update_frame_counter(1);
            if (m_rate_limiter.check_frame_skip(flow_id)) {
                LOG(DEBUG) << "Skipping flow " << flow_id << ": frame" << frame_num;
                m_skipped_frames++;
                output_elem = output_map.erase(output_elem);
                continue;
            }

            if (!send_msg(m_ui_sd, messages::tcp_sender::EVENT_FRAME_READY, &output.result)) {
                m_rate_limiter.update_dropped_frames(1);
                LOG(ERROR) << "Failed sending message MSTREAM_EVENT_FRAME_READY!";
                output_elem = output_map.erase(output_elem);
                continue;
            }

            if (m_ui_sd->writeBytes(frame_ptr, output.result.frame_size()) < 0) {
                m_rate_limiter.update_dropped_frames(1);
                LOG(ERROR) << "Failed sending frame payload!";
                output_elem = output_map.erase(output_elem);
                continue;
            }

            m_sent_frames++;
            m_sent_bytes += sizeof(imif::messages::sProtoHeader) + output.result.ByteSizeLong() + output.result.frame_size();
        }

        output_elem = output_map.erase(output_elem);
    }
}

std::shared_ptr<uint8_t> tcp_sender_thread::alloc_shared_ptr_buffer(ssize_t size, std::string name)
{
    auto s_ptr = std::shared_ptr<uint8_t>(new uint8_t[size_t(size)], [](uint8_t *obj) {
        if (obj)
            delete[] obj;
    });
    if (!s_ptr) {
        LOG(ERROR) << "Alloc s_ptr fail!!!, name: " << name;
    }
    return s_ptr;
}

void tcp_sender_thread::resize_frame_i420(uint8_t *input_ptr, messages::types::ResultReady &output, const size_t src_height,
                                          const size_t src_width)
{
    const size_t image_size = src_width * src_height;
    const size_t output_image_size = m_output_width * m_output_height;
    const ssize_t output_image_bytes = output_image_size * 1.5;
    const double width_ratio = double(m_output_width) / src_width;
    const double height_ratio = double(m_output_height) / src_height;

    if (output_image_bytes > m_resize_out_buff_bytes){
        m_resize_out_buff = alloc_shared_ptr_buffer(output_image_bytes, "m_resize_out_buff");
        if (!m_resize_out_buff) {
            m_resize_out_buff_bytes = 0;
            LOG(ERROR) << "Can't allocate memory for resize";
            return;
        }
        m_resize_out_buff_bytes = output_image_bytes;
    }

    uint8_t *out_ptr = m_resize_out_buff.get();

    Mat Yplane = Mat(src_height, src_width, CV_8UC1, input_ptr);
    Mat Yplane_resized = Mat(m_output_height, m_output_width, CV_8UC1, out_ptr);
    resize(Yplane, Yplane_resized, Yplane_resized.size());

    input_ptr += image_size;
    out_ptr += output_image_size;

    Mat Uplane = Mat(src_height / 2, src_width / 2, CV_8UC1, input_ptr);
    Mat Uplane_resized = Mat(m_output_height / 2, m_output_width / 2, CV_8UC1, out_ptr);
    resize(Uplane, Uplane_resized, Uplane_resized.size());

    input_ptr += image_size / 4;
    out_ptr += output_image_size / 4;

    Mat Vplane = Mat(src_height / 2, src_width / 2, CV_8UC1, input_ptr);
    Mat Vplane_resized = Mat(m_output_height / 2, m_output_width / 2, CV_8UC1, out_ptr);
    resize(Vplane, Vplane_resized, Uplane_resized.size());

    output.mutable_frame_info()->mutable_frame()->set_height(m_output_height);
    output.mutable_frame_info()->mutable_frame()->set_width(m_output_width);
    output.mutable_frame_info()->mutable_frame()->set_format("i420");
    output.set_frame_size(output_image_bytes);

    // Resize the bounding boxes
    for (auto &object : *output.mutable_detected_object()) {
        if (object.has_box()) {
            object.mutable_box()->set_height(object.box().height() * height_ratio);
            object.mutable_box()->set_width(object.box().width() * width_ratio);
            object.mutable_box()->set_coordiatex(object.box().coordiatex() * width_ratio);
            object.mutable_box()->set_coordiatey(object.box().coordiatey() * height_ratio);
        }
    }
}

void tcp_sender_thread::convert_and_resize_nv12_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output)
{
    const size_t width = output.frame_info().frame().width();
    const size_t height = output.frame_info().frame().height();
    const ssize_t rgb_image_bytes = width * height * 3;
    const ssize_t i420_image_bytes = width * height * 1.5;

    if (rgb_image_bytes > m_resize_rgb_image_buff_bytes) {
        m_resize_rgb_image_buff = alloc_shared_ptr_buffer(rgb_image_bytes, "m_resize_rgb_image_buff");
        if (!m_resize_rgb_image_buff) {
            m_resize_rgb_image_buff_bytes=0;
            LOG(ERROR) << "Can't allocate memory tor resize";
            return;
        }
        m_resize_rgb_image_buff_bytes = rgb_image_bytes;
    }
    uint8_t *rgb_image = m_resize_rgb_image_buff.get();

    if (i420_image_bytes > m_resize_i420_image_buff_bytes) {
        m_resize_i420_image_buff = alloc_shared_ptr_buffer(i420_image_bytes, "m_resize_i420_image_buff");
        if (!m_resize_i420_image_buff) {
            m_resize_i420_image_buff_bytes = 0;
            LOG(ERROR) << "Can't allocate memory tor resize";
            return;
        }
        m_resize_i420_image_buff_bytes = i420_image_bytes;
    }
    uint8_t *i420_image = m_resize_i420_image_buff.get();

    Mat src_image = Mat(height * 1.5, width, CV_8UC1, input_ptr);
    Mat rgb_mat = Mat(height, width, CV_8UC3, rgb_image);
    cv::cvtColor(src_image, rgb_mat, CV_YUV2RGB_NV12);

    Mat i420_mat = Mat(height * 1.5, width, CV_8UC1, i420_image);
    cv::cvtColor(rgb_mat, i420_mat, CV_RGB2YUV_I420);

    resize_frame_i420(i420_image, output, height, width);
}

void tcp_sender_thread::convert_and_resize_bgra_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output)
{
    const size_t src_width = output.frame_info().frame().width();
    const size_t src_height = output.frame_info().frame().height();
    // i420 does not support odd dimensions so we clip the last row/coloumn if needed
    const size_t width = src_width & ~1;
    const size_t height = src_height & ~1;
    const ssize_t i420_image_bytes = width * height * 1.5;

    if ( i420_image_bytes > m_resize_i420_image_buff_bytes ) {
        m_resize_i420_image_buff = alloc_shared_ptr_buffer(i420_image_bytes, "m_resize_i420_image_buff");
        if (!m_resize_i420_image_buff) {
            m_resize_i420_image_buff_bytes = 0;
            LOG(ERROR) << "Can't allocate memory tor resize";
            return;
        }
        m_resize_i420_image_buff_bytes = i420_image_bytes;
    }
    uint8_t *i420_image = m_resize_i420_image_buff.get();

    Mat src_image = Mat(src_height, src_width, CV_8UC3, input_ptr).rowRange(0, height).colRange(0, width);
    Mat i420_mat = Mat(height * 1.5, width, CV_8UC1, i420_image);
    cv::cvtColor(src_image, i420_mat, CV_BGRA2YUV_I420);

    resize_frame_i420(i420_image, output, height, width);
}

void tcp_sender_thread::convert_and_resize_rgb_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output)
{
    const size_t src_width = output.frame_info().frame().width();
    const size_t src_height = output.frame_info().frame().height();
    // i420 does not support odd dimensions so we clip the last row/coloumn if needed
    const size_t width = src_width & ~1;
    const size_t height = src_height & ~1;
    const ssize_t i420_image_bytes = width * height * 1.5;

    if ( i420_image_bytes > m_resize_i420_image_buff_bytes ) {
        m_resize_i420_image_buff = alloc_shared_ptr_buffer(i420_image_bytes, "m_resize_i420_image_buff");
        if (!m_resize_i420_image_buff) {
            m_resize_i420_image_buff_bytes = 0;
            LOG(ERROR) << "Can't allocate memory tor resize";
            return;
        }
        m_resize_i420_image_buff_bytes = i420_image_bytes;
    }
    uint8_t *i420_image = m_resize_i420_image_buff.get();

    Mat src_image = Mat(src_height, src_width, CV_8UC3, input_ptr).rowRange(0, height).colRange(0, width);
    Mat i420_mat = Mat(height * 1.5, width, CV_8UC1, i420_image);
    cv::cvtColor(src_image, i420_mat, CV_RGB2YUV_I420);

    resize_frame_i420(i420_image, output, height, width);
}

bool tcp_sender_thread::add_config(const messages::types::Config &config)
{
    messages::types::CustomConfig custom_config;
    if (!config.config().UnpackTo(&custom_config)) {
        LOG(ERROR) << "Unknown config proto!";
        return false;
    }

    uint32_t port = 0;
    auto elem = custom_config.config_map().find("port");
    if (elem != custom_config.config_map().end()) {
        port = common::string_utils::stou(elem->second);
    }

    if (port == 0) {
        port = messages::enums::Consts::TCP_VIDEO_PORT;
    }

    elem = custom_config.config_map().find("subnet");
    if (elem == custom_config.config_map().end()) {
        LOG(ERROR) << "No ip subnet in configuration!";
        return false;
    }

    std::string ip_addr = get_ip_addr(elem->second);
    if (ip_addr.empty()) {
        LOG(ERROR) << "Failed getting ip address for subnet " << elem->second;
        return false;
    }

    if (m_tcp_server_socket) {
        del_socket(m_tcp_server_socket);
    }

    m_tcp_server_socket = std::make_shared<SocketServer>(port, 10, ip_addr);
    if (!m_tcp_server_socket) {
        LOG(ERROR) << "tcp_server_socket == nullptr";
        return false;
    }
    const auto error_msg = m_tcp_server_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "tcp_server_socket error: " << error_msg;
        m_tcp_server_socket.reset();
        return false;
    }

    LOG(INFO) << "new SocketServer on TCP port " << port << " ip " << ip_addr;

    if (!add_socket(m_tcp_server_socket)) {
        LOG(ERROR) << "Failed adding the broker socket into the poll";
        return false;
    }

    return true;
}

bool tcp_sender_thread::remove_config(uint32_t config_id)
{
    LOG(INFO) << "ADDING CONFIG: " << config_id;
    return true;
}

bool tcp_sender_thread::add_flow(const messages::types::Flow &flow)
{
    uint32_t flow_id = flow.id();
    if (m_flow2stageid.find(flow_id) != m_flow2stageid.end()) {
        LOG(ERROR) << "Can't add flow " << flow_id << "- already exist!";
        return false;
    }

    // Make sure that tcp_sender isn't responsible for more then 1 stage
    uint32_t stages =
        std::count_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });
    if (stages > 1) {
        LOG(ERROR) << "Invalid flow configuration - tcp_sender participate more then once";
        return false;
    } else if (stages == 0) {
        LOG(DEBUG) << "tcp_sender does not participate in this flow " << flow_id;
        return true;
    }

    auto stage_it =
        std::find_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });

    LOG(DEBUG) << "ADDING FLOW id " << flow_id << " at stage " << stage_it->id();

    m_flow2stageid[flow_id] = stage_it->id();

    return true;
}

bool tcp_sender_thread::remove_flow(uint32_t flow_id)
{
    LOG(TRACE) << "REMOVE FLOW: " << flow_id;
    if (m_flow2stageid.find(flow_id) != m_flow2stageid.end()) {
        LOG(ERROR) << "Unknown flow_id " << flow_id;
        return false;
    }

    m_flow2stageid.erase(flow_id);

    m_output_map.erase(flow_id);
    for (auto &shmkey : m_flow2shmkey[flow_id]) {
        common::shmem_buff_factory::free_shmem_pool(shmkey);
    }
    m_flow2shmkey.erase(flow_id);

    return true;
}

void tcp_sender_thread::handle_enable()
{
    m_last_cleanup = m_last_stats = m_start_time = std::chrono::steady_clock::now();
    m_next_frame_rate_update = std::chrono::steady_clock::now() + std::chrono::microseconds(FRAME_RATE_INTRVAL_MSEC);
    m_total_received_bytes = m_total_sent_bytes = 0;
}

void tcp_sender_thread::handle_disable()
{
    clearOutputMap();
    m_ui_sd = nullptr;
    m_output_stream_flow_ids.clear();
}

bool tcp_sender_thread::global_config(const messages::mgmt::GlobalConfig global_config) { return true; }
