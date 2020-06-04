
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

#ifndef _MGMT_LIBSRV_H
#define _MGMT_LIBSRV_H

#include "mgmt_thread.h"
#include <grpcpp/grpcpp.h>
#include <messages/grpc/mgmt_ext_services.grpc.pb.h>
#include <messages/proto/mgmt_ext.pb.h>
#include <messages/proto/types.pb.h>
#include <set>

namespace imif {
namespace mgmt {

class management_library_server_thread;
//class MgmtThread;
// Base class used to cast the void* tags we get from
// the completion queue and call Process() on them.
class base_call_data {
public:
    base_call_data();
    virtual ~base_call_data();
    virtual void process(MgmtThread *this_thread) = 0;
    virtual void finish(bool success);

    void deallocate();

    static base_call_data *validate_cast(void *ptr);
    static void init(imif::services::mgmt_ext::MgmtLibrary::AsyncService *service, grpc::ServerCompletionQueue *cq);

protected:
    static imif::services::mgmt_ext::MgmtLibrary::AsyncService *s_service;

    static grpc::ServerCompletionQueue *s_cq;

    grpc::ServerContext m_ctx;

    enum CallStatus { INIT, READY, PROCESS, FINISH, XFERING };

    CallStatus m_status;

    static std::set<void *> s_all_calls;
};

class set_status_call_data : public base_call_data {
public:
    set_status_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::ModuleStatus m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class get_status_call_data : public base_call_data {
public:
    get_status_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::AllModulesStatus> m_responder;
    imif::messages::mgmt_ext::AllModulesStatusRequest m_command;
    imif::messages::mgmt_ext::AllModulesStatus m_output;
};

class ping_call_data : public base_call_data {
public:
    ping_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::IncomingPing> m_responder;
    imif::messages::mgmt_ext::OutgoingPing m_command;
    imif::messages::mgmt_ext::IncomingPing m_output;
};

class reset_call_data : public base_call_data {
public:
    reset_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::ResetCmd m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class request_id_call_data : public base_call_data {
public:
    request_id_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ListenID> m_responder;
    imif::messages::mgmt_ext::ListenerIDRequest m_command;

    imif::messages::mgmt_ext::ListenID m_output;
};

class subscribe_call_data : public base_call_data {
public:
    subscribe_call_data(management_library_server_thread *server);
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::SubscriptionRequest m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
    management_library_server_thread *m_server = nullptr;
};

class push_file_call_data : public base_call_data {
public:
    push_file_call_data();

    void process(MgmtThread *mgmt_thread);

    void set_success(bool success) { m_output.set_success(success); }

private:
    //grpc::ServerAsyncReader< ::imif::messages::mgmt_ext::ReturnStatus, ::imif::messages::mgmt_ext::Chunk> m_reader;
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::PushResponse> m_responder;
    imif::messages::mgmt_ext::FileChunk m_command;
    //imif::messages::mgmt_ext::PushRequest m_push_request;
    imif::messages::mgmt_ext::PushResponse m_output;
    static std::map<uint64_t, imif::messages::mgmt_ext::PushRequest> s_push_requests;
    friend class push_call_data;
};

class push_call_data : public base_call_data {
public:
    push_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::PushResponse> m_responder;
    imif::messages::mgmt_ext::PushRequest m_command;
    imif::messages::mgmt_ext::PushResponse m_output;
};

class pull_call_data : public base_call_data {
public:
    pull_call_data();
    void process(MgmtThread *mgmt_thread);
    bool send_file(std::string filename);
    void send_chunk(const std::string &chunk);
    void set_last_chunk();

private:
    grpc::ServerAsyncWriter<imif::messages::mgmt_ext::Chunk> m_responder;
    imif::messages::mgmt_ext::PushRequest m_command;
    imif::messages::mgmt_ext::Chunk m_output;
    uint64_t m_file_pos = 0;
    std::string m_filename;
};

class listen_call_data : public base_call_data, public subscriber {
public:
    listen_call_data(management_library_server_thread *server);

    void process(MgmtThread *mgmt_thread);
    void publish_event(std::string module_name, std::string message) override;
    void stop_listening();

private:
    void publish_event_safe(std::string module_name, std::string message);
    grpc::ServerAsyncWriter<imif::messages::mgmt_ext::Event> m_responder;
    imif::messages::mgmt_ext::ListenID m_command;
    std::queue<std::pair<std::string, std::string>> m_outstanding_events;
    std::recursive_mutex m_publishing_mutex;
    uint32_t m_id;
    management_library_server_thread *m_server = nullptr;
};

class workgroup_add_call_data : public base_call_data {
public:
    workgroup_add_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::WorkgroupID> m_responder;
    imif::messages::mgmt_ext::AddWorkgroup m_command;
    imif::messages::mgmt_ext::WorkgroupID m_output;
};

class workgroup_name_call_data : public base_call_data {
public:
    workgroup_name_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::NameWorkgroup m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class workgroup_getid_call_data : public base_call_data {
public:
    workgroup_getid_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::WorkgroupID> m_responder;
    imif::messages::mgmt_ext::NameWorkgroup m_command;
    imif::messages::mgmt_ext::WorkgroupID m_output;
};

class source_add_call_data : public base_call_data {
public:
    source_add_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::SourceAdd m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class source_start_call_data : public base_call_data {
public:
    source_start_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt::StartSource m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class flow_add_call_data : public base_call_data {
public:
    flow_add_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::FlowAdd m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class remove_item_call_data : public base_call_data {
public:
    remove_item_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::RemoveItem m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class request_command_call_data : public base_call_data {
public:
    request_command_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt::Command m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class config_add_call_data : public base_call_data {
public:
    config_add_call_data();
    void process(MgmtThread *mgmt_thread);
    virtual void finish(bool success) override;

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt::AddConfig m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class set_log_level_call_data : public base_call_data {
public:
    set_log_level_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ReturnStatus> m_responder;
    imif::messages::mgmt_ext::SetLogLevel m_command;
    imif::messages::mgmt_ext::ReturnStatus m_output;
};

class list_call_data : public base_call_data {
public:
    list_call_data();
    void process(MgmtThread *mgmt_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::mgmt_ext::ListResponse> m_responder;
    imif::messages::mgmt_ext::ListRequest m_command;
    imif::messages::mgmt_ext::ListResponse m_output;
};

class management_library_server_thread : public common::thread_base {
public:
    management_library_server_thread(int fd) : m_fd(fd) { m_listener_map.clear(); }

    ~management_library_server_thread() {}

    bool start_grpc_server(const std::string &port);

    void handle_cq_entry();

    bool register_listener(uint32_t listener_id, listen_call_data *call_data);
    void remove_listener(uint32_t listener_id);
    listen_call_data *listener_by_id(uint32_t listener_id);

protected:
    virtual void before_stop() override;
    virtual void on_thread_stop() override;
    virtual bool init() override;
    virtual bool work() override;

private:
    std::unique_ptr<grpc::ServerCompletionQueue> m_cq = nullptr;
    imif::services::mgmt_ext::MgmtLibrary::AsyncService m_service;

    std::unique_ptr<grpc::Server> m_server = nullptr;
    int m_fd;
    std::string m_mgmt_port;
    bool m_server_started = false;

    std::map<size_t, listen_call_data *> m_listener_map;
};

} // namespace mgmt
} // namespace imif
#endif
