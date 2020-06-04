
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

#pragma once

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_event_queue.h"
#include "common_mem_manager.h"

#include "rtsp_client.h"
#include "rtsp_util_thread.h"

#include <chrono>
#include <unordered_map>

#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>

namespace imif {
namespace mstream {

class mstream_rtsp_thread : public common::thread_base {
public:
    mstream_rtsp_thread(const std::string broker_uds);
    ~mstream_rtsp_thread();

    bool get_playing_source(uint32_t source_id);

    uint64_t sent_bytes() { return m_sent_bytes; }
    uint64_t dropped_bytes() { return m_dropped_bytes; }
    void reset_stats() { m_sent_bytes = m_dropped_bytes = 0; }

    void push_event(messages::enums::Opcode opcode, const google::protobuf::Message &msg);

protected:
    virtual void on_thread_stop() override;
    virtual bool init() override;
    virtual bool work() override;

private:
    bool get_frame_from_rtsp();
    bool rtsp_keep_alive();
    bool drop_frame(std::shared_ptr<RtspClientInst> rtspc_prt);
    bool create_shared_buff(uint32_t source_id);
    bool handle_msg(messages::enums::Opcode opcode, const void *msg, size_t msg_len);
    bool global_config(const messages::mgmt::GlobalConfig &global_config);
    bool add_source(const messages::types::Source &source);
    bool start_source(uint32_t source_id);
    bool remove_source(uint32_t source_id);
    bool add_flow(const messages::types::Flow &flow);
    bool remove_flow(uint32_t flow_id);
    bool add_config(const messages::types::Config &config);
    bool remove_config(uint32_t config_id);
    void handle_enable(bool enable);
    void reset();

private:
    std::string m_module_name = "";

    std::string m_broker_uds = "";
    std::string m_dump_path = "";
    std::shared_ptr<common::SocketClient> m_broker_socket = nullptr;
    std::shared_ptr<uint8_t> m_drop_buff = nullptr;

    bool m_enabled = false;

    std::unordered_map<uint32_t, std::shared_ptr<RtspClientInst>> m_rtsp_clients;       // key = source_id
    std::unordered_map<uint32_t, std::shared_ptr<imif::common::shmem_pool>> m_pool_map; // key = source_id
    std::unordered_map<uint32_t, std::list<uint32_t>> m_source_flows;                   // key = source_id -> list<flow_id's>
    std::unordered_map<uint32_t, uint32_t> m_flow_source;                               // key = flow_id -> source_id
    std::unordered_map<uint32_t, messages::types::Stage> m_flow_stages;                 // key = flow_id
    std::unordered_map<uint32_t, messages::mstream::Config> m_configs;                  // key = config_id
    struct current_buff {
        std::shared_ptr<imif::common::shmem_buff> buff = nullptr;
        size_t buff_written = 0;
        size_t buff_frame_boundary = 0;
        std::list<size_t> frame_sizes;
    };
    std::unordered_map<uint32_t, current_buff> m_current_map; // key = source_id

    uint64_t m_sent_bytes = 0;
    uint64_t m_dropped_bytes = 0;
    rtsp_util_thread m_rtsp_util_thread;

    common::event_queue m_event_queue;
};
} // namespace mstream
} // namespace imif
