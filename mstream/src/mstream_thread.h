
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

#ifndef _MSTREAM_THREAD_H
#define _MSTREAM_THREAD_H

#include "common_broker_thread.h"
#include "common_logging.h"

#include "mstream_grpc_server_thread.h"
#include "mstream_imageload_thread.h"
#include "mstream_rtsp_thread.h"

#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>

#include <chrono>
#include <unordered_map>

namespace imif {
namespace mstream {

class MstThread : public common::broker_thread {
public:
    MstThread(const std::string broker_uds, imif::common::logging *pLogger);
    ~MstThread();

    virtual bool post_init() override;
    virtual bool before_select() override;

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;

private:
    void reset();
    bool handle_enable();

    void log_stats(bool force = false);

    bool global_config(const messages::mgmt::GlobalConfig global_config);

    bool add_config(const messages::mgmt::AddConfig &config);
    bool add_source(const messages::mgmt::AddSource &source);
    bool add_flow(const messages::mgmt::AddFlow &flow);

    bool remove_config(const messages::mgmt::RemoveConfig &request);
    bool remove_source(const messages::mgmt::RemoveSource &request);
    bool remove_flow(const messages::mgmt::RemoveFlow &request);

    bool start_source(uint32_t source_id);
    bool stop_source(uint32_t source_id);

private:
    std::string m_module_name;

    std::string m_broker_uds;

    uint64_t m_dropped_bytes = 0;
    uint64_t m_sent_bytes = 0;
    uint64_t m_tcp_sent_bytes = 0;
    uint64_t m_total_dropped_bytes = 0;
    uint64_t m_total_sent_bytes = 0;
    uint64_t m_total_tcp_sent_bytes = 0;
    std::chrono::steady_clock::time_point m_start_time;
    std::chrono::steady_clock::time_point m_next_stats;

    std::chrono::steady_clock::time_point m_next_register;
    bool m_registered = false;
    bool m_enabled = false;

    std::set<uint32_t> m_rtsp_sources; // key = source_id
    std::set<uint32_t> m_rtsp_configs; // key = source_id

    std::unordered_map<uint32_t, messages::mstream::Config> m_configs; // key = config_id

    imif::common::logging *m_pLogger;

    std::shared_ptr<mstream_rtsp_thread> m_rtsp_thread = nullptr;
    std::map<uint32_t, std::shared_ptr<ImageLoadThread>> m_loadimage_threads;
    imif::mstream::GrpcServerThread m_grpc_server_thread;
};
} // namespace mstream
} // namespace imif

#endif
