
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

#ifndef _MGMT_THREAD_H
#define _MGMT_THREAD_H

#include "common_broker_thread.h"
#include "common_defines.h"
#include "common_logging.h"
#include "publisher.h"
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mgmt_ext.pb.h>

#include <messages/proto/types.pb.h>

#include <unordered_map>

namespace imif {
namespace mgmt {

class MgmtThread;
class base_call_data;
class listen_call_data;
class pull_call_data;
class push_file_call_data;

class MgmtThread : public common::broker_thread {
public:
    MgmtThread(std::string &broker_path, std::shared_ptr<common::Socket> ui_socket, imif::common::logging *pLogger);
    ~MgmtThread();

    virtual bool post_init() override;
    virtual bool before_select() override;

    bool enable_module(std::string module_name, bool enabled, std::string sub_module, int64_t wgid);
    void list_modules(imif::messages::mgmt_ext::AllModulesStatus &output);

    int64_t add_workgroup(std::string url, int port);
    bool remove_workgroup(int64_t wgid);

    bool add_source(const imif::messages::types::Source &source, int64_t wgid);
    bool remove_source(uint32_t source_id, int64_t wgid);
    bool start_source(uint32_t source_id, int64_t wgid);

    bool add_flow(messages::types::Flow &flow, int64_t wgid);
    bool remove_flow(uint32_t flow_id, int64_t wgid);

    bool add_config(imif::messages::mgmt::AddConfig &add_config, int64_t wgid);
    bool remove_config(const messages::mgmt_ext::RemoveItem &remove_config, int64_t wgid);

    void set_log_level(const imif::messages::mgmt_ext::SetLogLevel &request);

    void handle_subscribe(std::string topic, listen_call_data *listener, int64_t wgid);
    void handle_unsubscribe(std::string topic, listen_call_data *listener, int64_t wgid);

    bool verify_push(const std::string &filename, const std::string &module_name, int64_t wgid);
    bool handle_pull(std::string module_name, int64_t wgid, pull_call_data *call_data);
    bool send_chunk(const std::string &chunk, uint64_t file_pos, const std::string &filename, const std::string &module_name,
                    int64_t wgid, push_file_call_data *call_data);

    bool reset_module(std::string module_name, int64_t wgid);

    bool request_command(messages::mgmt::Command &command, int64_t wgid);

    void list(const imif::messages::mgmt_ext::ListRequest &request, imif::messages::mgmt_ext::ListResponse &response, int64_t wgid);

    int64_t get_workgroup_id(std::string name);
    bool set_workgroup_name(int32_t wgid, std::string name);
    std::string get_workgroup_name(int32_t wgid);

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override;
    virtual bool socket_disconnected(std::shared_ptr<common::Socket> sd) override;

private:
    void reset();
    void list_config(const imif::messages::mgmt_ext::ListRequest &request, imif::messages::mgmt_ext::ListResponse &response,
                     const std::map<uint32_t, messages::types::Config> &configs, std::string module_name, int64_t wgid);
    bool receive_logs(messages::mgmt::SendChunk &send_chunk);
    bool acknowledge_push(messages::mgmt::AckChunk &send_chunk);

private:
    struct pipe_member {
        bool registered = false;
        bool enabled = false;
        uint32_t assigned_id = 0;
    };

    struct workgroup_cfg {
        std::unordered_map<std::string, pipe_member> pipe_members;
        std::map<uint32_t, messages::types::Source> sources;
        std::map<std::string, std::map<uint32_t, messages::types::Config>> configs; // (module name) --> (cfg_id --> cfg)
        std::map<uint32_t, messages::types::Flow> flows;
        std::shared_ptr<common::SocketClient> broker_socket;
        publisher publisher_;
        uint32_t next_module_id = 0;
    };

    std::string m_module_name;
    std::string m_log_levels;
    int32_t m_next_wgid = 0;

    std::unordered_map<int32_t, workgroup_cfg> m_workgroups;
    std::unordered_map<int, int32_t> m_socket2wgid; // socket_fd --> wgid
    std::shared_ptr<common::Socket> m_ui_socket;

    std::set<std::pair<std::string, int32_t>> m_stat_topics; // {topic, wgid}
    imif::common::logging *m_pLogger;
    std::map<std::string, int64_t> m_wgname2id;
    std::map<int64_t, std::string> m_id2wgname;
    uint32_t m_next_file_reqid = 0;
    std::map<uint32_t, pull_call_data *> m_pull_responders;      // key = request_id
    std::map<uint32_t, push_file_call_data *> m_push_responders; // key = request_id
};

} // namespace mgmt
} // namespace imif

#endif
