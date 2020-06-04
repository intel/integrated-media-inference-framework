
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

#include "management_server.h"
#include "common_os_utils.h"
#include "mgmt_thread.h"

#include <grpcpp/grpcpp.h>
#include <unistd.h>

namespace imif {
namespace mgmt {

// declaring static variables for base_call_data:
std::set<void *> base_call_data::s_all_calls;

imif::services::mgmt_ext::MgmtLibrary::AsyncService *base_call_data::s_service;

grpc::ServerCompletionQueue *base_call_data::s_cq;

// keep pointers to the servers' service and cq, common to all calls.
void base_call_data::init(imif::services::mgmt_ext::MgmtLibrary::AsyncService *service, grpc::ServerCompletionQueue *cq)
{
    s_service = service;
    s_cq = cq;
}

base_call_data::base_call_data() : m_status(PROCESS)
{
    s_all_calls.insert(this); // keep track of allocated callDatas
}

base_call_data::~base_call_data() {}

void base_call_data::finish(bool success) {}

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
    } else {
        return nullptr;
    }
}

set_status_call_data::set_status_call_data() : m_responder(&m_ctx)
{
    s_service->RequestSetModuleStatus(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void set_status_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new set_status_call_data();
        LOG(INFO) << "got command to " << (m_command.enabled() ? "enable" : "disable") << " module: " << m_command.module_name();
        bool success =
            mgmt_thread->enable_module(m_command.module_name(), m_command.enabled(), m_command.sub_module(), m_command.wgid());
        m_output.set_success(success);

        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

get_status_call_data::get_status_call_data() : m_responder(&m_ctx)
{
    s_service->RequestRequestAllModulesStatus(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}
void get_status_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new get_status_call_data();
        LOG(INFO) << "got command to list modules";

        mgmt_thread->list_modules(m_output);

        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

ping_call_data::ping_call_data() : m_responder(&m_ctx)
{
    s_service->RequestPing(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}
void ping_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        LOG(INFO) << "Received ping" << std::endl;
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

reset_call_data::reset_call_data() : m_responder(&m_ctx)
{
    s_service->RequestReset(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}
void reset_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        LOG(INFO) << "Received Reset command" << std::endl;
        new reset_call_data();
        m_status = FINISH;
        bool result = mgmt_thread->reset_module(m_command.module_name(), m_command.wgid());
        m_output.set_success(result);
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

request_id_call_data::request_id_call_data() : m_responder(&m_ctx)
{
    s_service->RequestRequestListenerID(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}
void request_id_call_data::process(MgmtThread *mgmt_thread)
{
    static size_t s_next_id = 0;
    if (m_status == PROCESS) {
        new request_id_call_data();
        m_status = FINISH;
        m_output.set_listener_id(++s_next_id);
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}
push_file_call_data::push_file_call_data() : m_responder(&m_ctx)
{
    s_service->RequestPushFile(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}
std::map<uint64_t, imif::messages::mgmt_ext::PushRequest> push_file_call_data::s_push_requests;

void push_file_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        auto it = s_push_requests.find(m_command.tag());
        if (it == s_push_requests.end()) {
            LOG(ERROR) << "unrecognized tag";
            m_output.set_success(false);
            s_push_requests.erase(m_command.tag());
            m_responder.Finish(m_output, grpc::Status::CANCELLED, this);
            m_status = FINISH;
            return;
        }
        imif::messages::mgmt_ext::PushRequest pr = it->second;
        bool success =
            mgmt_thread->send_chunk(m_command.content(), m_command.file_pos(), pr.filename(), pr.module_name(), pr.wgid(), this);
        if (!success) {
            m_output.set_success(false);
            s_push_requests.erase(m_command.tag());
            m_responder.Finish(m_output, grpc::Status::CANCELLED, this);
            m_status = FINISH;
        } else {
            m_status = READY;
        }
    } else if (m_status == READY) {
        imif::messages::mgmt_ext::PushRequest pr = s_push_requests[m_command.tag()];
        if (m_command.is_last_chunk()) {
            s_push_requests.erase(m_command.tag());
        } else {
            uint64_t tag = (uint64_t) new push_file_call_data();
            m_output.set_tag(tag);
        }
        m_responder.Finish(m_output, grpc::Status::OK, this);
        m_status = FINISH;
    } else if (m_status == FINISH) {
        deallocate();
    }
}

push_call_data::push_call_data() : m_responder(&m_ctx)
{
    s_service->RequestPush(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void push_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new push_call_data();

        bool success = mgmt_thread->verify_push(m_command.filename(), m_command.module_name(), m_command.wgid());
        if (success) {
            auto tag = (uint64_t) new push_file_call_data();
            push_file_call_data::s_push_requests[(uint64_t)tag] = m_command;
            m_output.set_tag(tag);
        }

        m_output.set_success(success);
        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

pull_call_data::pull_call_data() : m_responder(&m_ctx)
{
    s_service->RequestPull(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
    m_status = INIT;
}

void pull_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == INIT) {
        new pull_call_data();
        if (!mgmt_thread->handle_pull(m_command.module_name(), m_command.wgid(), this)) {
            LOG(ERROR) << "Failed to pull file, canceling request";
            m_status = FINISH;
            m_responder.Finish(grpc::Status::CANCELLED, this);
        }
        m_status = XFERING;
    } else if (m_status == XFERING) { // ignore requests
    } else if (m_status == PROCESS) {
        send_file(m_filename);
    } else if (m_status == READY) {
        m_status = FINISH;
        m_responder.Finish(grpc::Status::OK, this);
    } else if (m_status == FINISH) {
        deallocate();
    }
}

void pull_call_data::send_chunk(const std::string &content)
{
    m_output.set_content(content);
    m_responder.Write(m_output, this);
}

void pull_call_data::set_last_chunk() { m_status = READY; }

bool pull_call_data::send_file(std::string filename)
{
    const uint64_t MAX_CHUNK_SIZE = 32768;
    std::ifstream input_stream(filename, std::ios::binary);
    m_filename = filename;
    if (!input_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << filename << " !!\n";
        return false;
    }
    char buffer[MAX_CHUNK_SIZE];
    input_stream.seekg(0, input_stream.end);
    uint64_t remaining_bytes = input_stream.tellg();
    input_stream.seekg(m_file_pos, input_stream.beg);
    remaining_bytes -= input_stream.tellg();
    uint64_t length;

    if (remaining_bytes <= MAX_CHUNK_SIZE) {
        length = remaining_bytes;
        m_status = READY;
    } else {
        m_status = PROCESS;
        length = MAX_CHUNK_SIZE;
    }

    input_stream.read(buffer, length);

    m_output.set_content(buffer, length);

    m_responder.Write(m_output, this);
    m_file_pos += length;

    input_stream.close();

    return true;
}

subscribe_call_data::subscribe_call_data(management_library_server_thread *server) : m_responder(&m_ctx), m_server(server)
{
    s_service->RequestSubscribe(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void subscribe_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new subscribe_call_data(m_server);
        listen_call_data *listener = m_server->listener_by_id(m_command.listener_id());
        if (listener == nullptr) {
            LOG(ERROR) << "Asked to subscribe to an unregistered listener_id";
            m_output.set_success(false);
        } else {
            if (m_command.subscribe()) {
                mgmt_thread->handle_subscribe(m_command.topic(), listener, m_command.wgid());
            } else {
                mgmt_thread->handle_unsubscribe(m_command.topic(), listener, m_command.wgid());
            }
            m_output.set_success(true);
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

listen_call_data::listen_call_data(management_library_server_thread *server) : m_responder(&m_ctx), m_server(server)
{
    s_service->RequestListen(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
    m_status = INIT;
}

void listen_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == INIT) {
        new listen_call_data(m_server);
        m_id = m_command.listener_id();

        if (!m_server->register_listener(m_id, this)) {
            LOG(ERROR) << "Failed to register listener";
            deallocate();
            return;
        }
        m_status = READY;
    } else if (m_status == PROCESS) {
        m_publishing_mutex.lock();
        m_status = READY;
        if (!m_outstanding_events.empty()) {
            auto module_name = std::get<0>(m_outstanding_events.front());
            auto msg = std::get<1>(m_outstanding_events.front());
            publish_event_safe(module_name, msg);
            m_outstanding_events.pop();
        }
        m_publishing_mutex.unlock();
    } else if (m_status == FINISH) {
        mgmt_thread->handle_unsubscribe("all", this, -1); // unsubscribe from all wg, all topics.
        m_server->remove_listener(m_id);
        deallocate();
    } // if m_status is READY, do nothing.
}

void listen_call_data::publish_event_safe(std::string module_name, std::string message)
{
    if (m_status == READY) {
        m_status = PROCESS;
        imif::messages::mgmt_ext::Event output;
        output.set_module_name(module_name);
        output.set_message(message);
        m_responder.Write(output, this);
    } else {
        m_outstanding_events.emplace(std::make_pair(module_name, message));
    }
}

void listen_call_data::publish_event(std::string module_name, std::string message)
{
    m_publishing_mutex.lock();
    publish_event_safe(module_name, message);
    m_publishing_mutex.unlock();
}

void listen_call_data::stop_listening() { m_status = FINISH; }

workgroup_add_call_data::workgroup_add_call_data() : m_responder(&m_ctx)
{
    s_service->RequestAddWorkgroup(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void workgroup_add_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new workgroup_add_call_data();
        auto wgid = mgmt_thread->add_workgroup(m_command.url(), m_command.port());
        m_output.set_wgid(wgid);
        finish(wgid >= 0);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}
void workgroup_add_call_data::finish(bool success)
{
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

workgroup_name_call_data::workgroup_name_call_data() : m_responder(&m_ctx)
{
    s_service->RequestNameWorkgroup(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void workgroup_name_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new workgroup_name_call_data();
        bool success = mgmt_thread->set_workgroup_name(m_command.wgid(), m_command.wgname());
        m_output.set_success(success);
        finish(success);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}
void workgroup_name_call_data::finish(bool success)
{
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

workgroup_getid_call_data::workgroup_getid_call_data() : m_responder(&m_ctx)
{
    s_service->RequestGetWorkgroupID(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void workgroup_getid_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new workgroup_getid_call_data();
        auto wgid = mgmt_thread->get_workgroup_id(m_command.wgname());
        m_output.set_wgid(wgid);
        finish(wgid >= 0);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}
void workgroup_getid_call_data::finish(bool success)
{
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

source_add_call_data::source_add_call_data() : m_responder(&m_ctx)
{
    s_service->RequestSourceAdd(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void source_add_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new source_add_call_data();

        finish(mgmt_thread->add_source(m_command.source(), m_command.wgid()));
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void source_add_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

source_start_call_data::source_start_call_data() : m_responder(&m_ctx)
{
    s_service->RequestSourceStart(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void source_start_call_data::process(MgmtThread *mgmt_thread)
{
    LOG(ERROR) << "start processing start calldata";
    if (m_status == PROCESS) {
        new source_start_call_data();

        finish(mgmt_thread->start_source(m_command.source_id(), m_command.wgid()));
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
    LOG(ERROR) << "end processing start calldata";
}

void source_start_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

flow_add_call_data::flow_add_call_data() : m_responder(&m_ctx)
{
    s_service->RequestFlowAdd(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void flow_add_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new flow_add_call_data();

        finish(mgmt_thread->add_flow(*m_command.mutable_flow(), m_command.wgid()));
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void flow_add_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

remove_item_call_data::remove_item_call_data() : m_responder(&m_ctx)
{
    s_service->RequestRemove(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void remove_item_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new remove_item_call_data();
        std::string item_name = m_command.item_name();
        if (item_name == "config") {
            finish(mgmt_thread->remove_config(m_command, m_command.wgid()));
        } else if (item_name == "source") {
            finish(mgmt_thread->remove_source(m_command.id(), m_command.wgid()));
        } else if (item_name == "flow") {
            finish(mgmt_thread->remove_flow(m_command.id(), m_command.wgid()));
        } else if (item_name == "workgroup") {
            finish(mgmt_thread->remove_workgroup(m_command.wgid()));
        } else {
            LOG(ERROR) << "Unexpected item name: " << item_name;
            finish(false);
        }
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void remove_item_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

config_add_call_data::config_add_call_data() : m_responder(&m_ctx)
{
    s_service->RequestAddConfig(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void config_add_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new config_add_call_data();

        finish(mgmt_thread->add_config(m_command, m_command.wgid()));
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void config_add_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

request_command_call_data::request_command_call_data() : m_responder(&m_ctx)
{
    s_service->RequestRequestCommand(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void request_command_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new request_command_call_data();
        LOG(INFO) << "MGMT_CUSTOM_COMMAND: " << m_command;

        finish(mgmt_thread->request_command(m_command, m_command.wgid()));
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

void request_command_call_data::finish(bool success)
{
    m_output.set_success(success);
    m_status = FINISH;
    m_responder.Finish(m_output, grpc::Status::OK, this);
}

set_log_level_call_data::set_log_level_call_data() : m_responder(&m_ctx)
{
    s_service->RequestLogLevelSet(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void set_log_level_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new set_log_level_call_data();

        mgmt_thread->set_log_level(m_command);

        m_output.set_success(true);
        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

list_call_data::list_call_data() : m_responder(&m_ctx)
{
    s_service->RequestList(&m_ctx, &m_command, &m_responder, s_cq, s_cq, this);
}

void list_call_data::process(MgmtThread *mgmt_thread)
{
    if (m_status == PROCESS) {
        new list_call_data();

        mgmt_thread->list(m_command, m_output, m_command.wgid());

        m_status = FINISH;
        m_responder.Finish(m_output, grpc::Status::OK, this);
    } else {
        if (m_status != FINISH) {
            LOG(ERROR) << "Unexpected status on call data: " << m_status;
        }
        deallocate();
    }
}

bool management_library_server_thread::init()
{
    LOG(TRACE) << "init()";
    return true;
}

bool management_library_server_thread::start_grpc_server(const std::string &port)
{
    m_mgmt_port = port;
    std::string server_address = std::string("0.0.0.0:") + m_mgmt_port;

    grpc::ServerBuilder builder;

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    builder.RegisterService(&m_service);

    m_cq = builder.AddCompletionQueue();
    if (!m_cq) {
        LOG(FATAL) << "Failed creating CQ!";
        should_stop = true;
        return false;
    }

    m_server = builder.BuildAndStart();
    if (!m_server) {
        should_stop = true;
        LOG(FATAL) << "Failed creating server!";
        return false;
    }

    LOG(INFO) << "grpc::Server listening on " << server_address;

    base_call_data::init(&m_service, m_cq.get());

    new set_status_call_data();
    new get_status_call_data();
    new ping_call_data();
    new request_id_call_data();
    new listen_call_data(this);
    new subscribe_call_data(this);
    new push_call_data();
    new pull_call_data();
    new workgroup_add_call_data();
    new workgroup_name_call_data();
    new workgroup_getid_call_data();
    new source_add_call_data();
    new source_start_call_data();
    new flow_add_call_data();
    new request_command_call_data();
    new config_add_call_data();
    new remove_item_call_data();
    new set_log_level_call_data();
    new reset_call_data();
    new list_call_data();

    m_server_started = true;

    return true;
}

void management_library_server_thread::before_stop()
{
    LOG(TRACE) << "before_stop()";
    if (should_stop) {
        if (m_server) {
            m_server->Shutdown();
        }
        if (m_cq) {
            // Always shutdown the completion queue after the grpc::Server.
            m_cq->Shutdown();
        }
    }
}

void management_library_server_thread::on_thread_stop() { LOG(TRACE) << "on_thread_stop()"; }

bool management_library_server_thread::work()
{
    handle_cq_entry();
    return true;
}

void management_library_server_thread::handle_cq_entry()
{
    if (!m_cq || !m_server || !m_server_started) {
        sleep(1);
        return;
    }
    void *tag;
    bool ok;
    bool ret = m_cq->Next(&tag, &ok);

    if ((ret) && (ok)) {
        write(m_fd, &tag, sizeof(void *));
    } else {
        LOG(DEBUG) << "Server detected aborted request! ret=" << ret << " ok=" << ok;
        listen_call_data *call_data = dynamic_cast<listen_call_data *>(base_call_data::validate_cast(tag));
        if (call_data) {
            call_data->stop_listening();
            write(m_fd, &tag, sizeof(void *));
        }
    }
}

bool management_library_server_thread::register_listener(uint32_t listener_id, listen_call_data *call_data)
{
    if (m_listener_map.find(listener_id) == m_listener_map.end()) {
        m_listener_map.insert(std::make_pair(listener_id, call_data));
        return true;
    } else {
        LOG(ERROR) << "Tried to register listener with an ID already in use: " << listener_id;
        return false;
    }
}

void management_library_server_thread::remove_listener(uint32_t listener_id) { m_listener_map.erase(listener_id); }

listen_call_data *management_library_server_thread::listener_by_id(uint32_t listener_id)
{
    auto it = m_listener_map.find(listener_id);
    if (it == m_listener_map.end()) {
        return NULL;
    }
    return it->second;
}
} // namespace mgmt
} // namespace imif
