
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

#include "../include/mgmt_lib.h"

#include "easylogging++.h"

#include <yaml_wrapper.h>

#include <common_os_utils.h>
#include <messages/proto/inference.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mstream.pb.h>

#include <exception>
#include <limits>

using namespace imif;
using namespace imif_yaml;
using namespace mgmt;
using namespace common;

bool get_string_sequence(yaml_node &config, std::string key, std::vector<std::string> &out_vec)
{
    auto yaml_item = config[key];
    if (yaml_item && yaml_item.is_sequence()) {
        for (auto item : yaml_item) {
            out_vec.push_back(item->scalar());
        }
    }
    return (out_vec.size() > 0);
}

std::string prep_rtsp_url_list(std::vector<std::string> &url_list)
{
    std::string ret_error = "";
    bool seq = false;
    int max_loops = 10;
    std::string seq_dl1 = "|";
    std::string seq_dl2 = "-";
    std::size_t seq_dl_idx = 0;

    for (int loop = 0; loop < max_loops; loop++) {
        seq = false;
        int uri_idx = 0;
        for (; uri_idx < int(url_list.size()); uri_idx++) {
            seq_dl_idx = url_list[uri_idx].find(seq_dl1);
            if (seq_dl_idx != std::string::npos) {
                seq = true;
                break;
            }
        }
        if (seq) {
            auto uri_val = url_list[uri_idx].substr(0, seq_dl_idx);
            auto uri_seq = url_list[uri_idx].substr(seq_dl_idx + 1, url_list[uri_idx].size());
            std::size_t seq_dl2_idx = uri_seq.find(seq_dl2);
            if (seq_dl2_idx == std::string::npos) {
                ret_error = "Yaml config item: rtsp_uri error in value: " + url_list[uri_idx];
                return ret_error;
            }
            int seq_start, seq_end;
            try {
                seq_start = common::string_utils::stou(uri_seq.substr(0, seq_dl2_idx));
                seq_end = common::string_utils::stou(uri_seq.substr(seq_dl2_idx + 1, uri_seq.size()));
            } catch (std::exception e) {
                ret_error = "Yaml config item: Failed to parse url: " + url_list[uri_idx];
                return ret_error;
            }
            auto seq_size = seq_end - seq_start + 1;
            if (seq_size <= 0 || seq_size > 200) {
                ret_error = "Yaml config item: rtsp_uri error in value: " + url_list[uri_idx];
                return ret_error;
            }
            url_list.erase(url_list.begin() + uri_idx);
            for (int idx = 0; idx < seq_size; idx++) {
                url_list.insert(url_list.begin() + uri_idx + idx, uri_val + std::to_string(seq_start + idx));
            }
        } else {
            break;
        }
    }
    return ret_error;
}

management_client::management_client() {}

management_client::~management_client() { disconnect(); }

bool management_client::connect(std::string &host_or_ip_str, std::string &port_str)
{
    disconnect();

    std::string connection_string;
    connection_string.append(host_or_ip_str);
    connection_string.append(":");
    connection_string.append(port_str);
    LOG(INFO) << "Connecting to: " << connection_string;
    m_channel = grpc::CreateChannel(connection_string, grpc::InsecureChannelCredentials());
    m_stub = imif::services::mgmt_ext::MgmtLibrary::NewStub(m_channel);
    if (!m_stub) {
        LOG(ERROR) << "Failed to create channel.";
        m_channel = nullptr;
        return false;
    }
    bool ping_result = ping();
    if (!ping_result) {
        m_stub = nullptr;
        m_channel = nullptr;
        return false;
    }

    m_listener_id = request_id();
    if (!listen()) {
        m_stub = nullptr;
        m_channel = nullptr;
        return false;
    }
    return true;
}

void management_client::disconnect()
{
    if (m_channel) {
        LOG(DEBUG) << "Disconnecting...";
    }

    stop_listen();

    if (m_stub)
        m_stub.reset();
    if (m_channel)
        m_channel.reset();
}

void management_client::stop_listen()
{
    m_running.store(false);
    if (m_listener_context) {
        m_listener_context->TryCancel(); // releases m_event_dispatch_thread from Next(), stopping it.
    }

    grpc::Status status;
    void *tag;
    if (m_event_reader) {
        m_event_reader->Finish(&status, &tag);
    }
    if (!status.ok()) {
        LOG(ERROR) << "Finish when disconnecting returned status that is not ok! " << status.error_message();
    }
    if (m_cq) {
        m_cq->Shutdown();
        bool ok;
        while (m_cq->Next(&tag, &ok)) {
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

bool management_client::set_module_state(std::string module_name, bool enabled, int64_t wgid, std::string sub_module)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }
    imif::messages::mgmt_ext::ModuleStatus module_status;
    module_status.set_module_name(module_name);
    module_status.set_enabled(enabled);
    module_status.set_sub_module(sub_module);
    module_status.set_wgid(wgid);

    grpc::ClientContext context;
    imif::messages::mgmt_ext::ReturnStatus return_value;
    LOG(INFO) << "Setting: " << module_name << " <" << sub_module << "> to be " << (enabled ? "enabled" : "disabled");
    grpc::Status status = m_stub->SetModuleStatus(&context, module_status, &return_value);

    if (!check_error(status)) {
        return false;
    }

    //LOG(INFO) << "Return value: " << return_value.success();
    return return_value.success();
}

void management_client::get_module_list(imif::messages::mgmt_ext::AllModulesStatus *all_modules_status)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return;
    }

    imif::messages::mgmt_ext::AllModulesStatusRequest allModulesStatusRequest;
    // Data we are sending to the server.
    grpc::ClientContext context;
    grpc::Status status = m_stub->RequestAllModulesStatus(&context, allModulesStatusRequest, all_modules_status);
    check_error(status);
}

void management_client::list(std::string item_name, std::string module, imif::messages::mgmt_ext::ListResponse *list_response,
                             int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return;
    }
    imif::messages::mgmt_ext::ListRequest list_request;
    list_request.set_item_name(item_name);
    list_request.set_module(module);
    list_request.set_all(true);
    list_request.set_wgid(wgid);

    grpc::ClientContext context;
    grpc::Status status = m_stub->List(&context, list_request, list_response);
    check_error(status);
}

void management_client::list(std::string item_name, std::string module, uint32_t id,
                             imif::messages::mgmt_ext::ListResponse *list_response, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return;
    }
    imif::messages::mgmt_ext::ListRequest list_request;
    list_request.set_item_name(item_name);
    list_request.set_module(module);
    list_request.set_id(id);
    list_request.set_wgid(wgid);

    grpc::ClientContext context;
    grpc::Status status = m_stub->List(&context, list_request, list_response);
    check_error(status);
}

bool management_client::ping()
{
    if (!m_stub) {
        LOG(ERROR) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::OutgoingPing out_ping;
    imif::messages::mgmt_ext::IncomingPing in_ping;
    grpc::ClientContext context;

    grpc::Status status = m_stub->Ping(&context, out_ping, &in_ping);
    return check_error(status);
}

bool management_client::send_reset(std::string module_name, int64_t wgid)
{
    if (!m_stub) {
        LOG(ERROR) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::ResetCmd resetCmd;
    resetCmd.set_module_name(module_name);
    resetCmd.set_wgid(wgid);
    imif::messages::mgmt_ext::ReturnStatus returnStatus;

    grpc::ClientContext context;
    grpc::Status status = m_stub->Reset(&context, resetCmd, &returnStatus);
    return check_error(status);
}

uint32_t management_client::request_id()
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::ListenerIDRequest listenerIDRequest;
    imif::messages::mgmt_ext::ListenID listen_id;
    grpc::ClientContext context;

    grpc::Status status = m_stub->RequestListenerID(&context, listenerIDRequest, &listen_id);
    if (!check_error(status)) {
        return 0;
    } else {
        m_listener_id = listen_id.listener_id();
        return m_listener_id;
    }
}

bool management_client::subscribe(std::string topic, bool subscribe, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::SubscriptionRequest subscriptionRequest;

    subscriptionRequest.set_listener_id(m_listener_id);
    subscriptionRequest.set_subscribe(subscribe);
    subscriptionRequest.set_topic(topic);
    subscriptionRequest.set_wgid(wgid);

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status = m_stub->Subscribe(&context, subscriptionRequest, &mgmtReturnStatus);
    if (!check_error(status)) {
        return false;
    } else {
        return mgmtReturnStatus.success();
    }
}

bool management_client::read_file_chunk(const std::string &filename, char *buffer, int64_t &file_pos, int64_t &length,
                                        bool &is_done)
{
    std::ifstream input_stream(filename, std::ios::binary);
    if (!input_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << filename << " !!\n";
        return false;
    }
    input_stream.seekg(0, input_stream.end);
    uint64_t remaining_bytes = input_stream.tellg();
    input_stream.seekg(file_pos, input_stream.beg);
    remaining_bytes -= input_stream.tellg();

    if (remaining_bytes <= MAX_CHUNK_SIZE) {
        length = remaining_bytes;
        is_done = true;
    } else {
        length = MAX_CHUNK_SIZE;
    }

    input_stream.read(buffer, length);

    file_pos += length;

    input_stream.close();

    return true;
}

bool management_client::push_file(const std::string &filename, void *tag)
{
    char buffer[MAX_CHUNK_SIZE];
    int64_t file_pos = 0;
    int64_t length = 0;
    bool is_done = false;

    std::shared_ptr<grpc::ClientContext> context = std::make_shared<grpc::ClientContext>();
    imif::messages::mgmt_ext::FileChunk chunk;
    chunk.set_tag((uint64_t)tag);

    imif::messages::mgmt_ext::PushResponse push_response;

    while (!is_done) {
        chunk.set_file_pos(file_pos);
        if (!read_file_chunk(filename, buffer, file_pos, length, is_done)) {
            return false;
        }
        chunk.set_content(buffer, length);
        chunk.set_is_last_chunk(is_done);

        grpc::Status status = m_stub->PushFile(context.get(), chunk, &push_response);
        if (!check_error(status)) {
            return false;
        }
        if (push_response.success()) {
        } else {
            LOG(INFO) << "Failed pushing file: " << filename;
            return false;
        }
        context = std::make_shared<grpc::ClientContext>();
    }
    LOG(INFO) << "Done sending file: " << filename;

    return true;
}

bool management_client::push(const std::string &filename, std::string module_name, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::PushRequest pushRequest;

    pushRequest.set_filename(filename);
    pushRequest.set_module_name(module_name);
    pushRequest.set_wgid(wgid);
    pushRequest.set_push_or_pull(true);

    grpc::ClientContext context;
    imif::messages::mgmt_ext::PushResponse push_response;

    grpc::Status status = m_stub->Push(&context, pushRequest, &push_response);
    if (!check_error(status)) {
        return false;
    }
    if (!push_response.success()) {
        LOG(INFO) << "Failed push request " << filename << " to " << module_name << ":" << wgid;
        return false;
    }
    push_file(filename, (void *)push_response.tag());
    return true;
}

bool management_client::pull(std::string module_name, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::PushRequest pushRequest;

    pushRequest.set_module_name(module_name);
    pushRequest.set_wgid(wgid);
    pushRequest.set_push_or_pull(false);

    grpc::ClientContext context;
    std::string filename = module_name + "_logs.tar.gz";
    std::string target_dir = "logs";
    std::string target_path = target_dir + "/" + filename;
    os_utils::make_dir(target_dir);
    auto cq = std::make_shared<grpc::CompletionQueue>();
    if (!cq) {
        LOG(ERROR) << "Failed to create cq!";
        return false;
    }

    std::unique_ptr<::grpc::ClientAsyncReaderInterface<::imif::messages::mgmt_ext::Chunk>> event_reader =
        m_stub->AsyncPull(&context, pushRequest, cq.get(), this);
    if (!event_reader) {
        LOG(ERROR) << "Failed to pull!";
        return false;
    }
    std::ofstream output_stream(target_path, std::ios::binary); // overwrite possible existing file with the new one.
    if (!output_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << filename << " for writing!!\n";
        return false;
    }
    imif::messages::mgmt_ext::Chunk file;
    void *got_tag;
    bool ok = false;

    while (cq->Next(&got_tag, &ok)) {
        if (ok) {
            event_reader->Read(&file, got_tag);
            output_stream << file.content();
        } else {
            break;
        }
    }
    grpc::Status status;

    event_reader->Finish(&status, &got_tag);
    output_stream.close();

    LOG(INFO) << "Pulled logs from " << module_name << ":" << wgid << " to: " << target_path;

    return true;
}

bool management_client::listen()
{
    m_listener_context = std::make_shared<grpc::ClientContext>();
    if (!m_listener_context) {
        LOG(ERROR) << "Failed to create ClientContext!";
        return false;
    }
    m_cq = std::make_shared<grpc::CompletionQueue>();
    if (!m_cq) {
        m_listener_context = nullptr;
        LOG(ERROR) << "Failed to create cq!";
        return false;
    }
    // open the event source:
    imif::messages::mgmt_ext::ListenID listenID;
    listenID.set_listener_id(m_listener_id);

    m_event_reader = m_stub->AsyncListen(m_listener_context.get(), listenID, m_cq.get(), this);
    if (!m_event_reader) {
        m_cq = nullptr;
        m_listener_context = nullptr;
        LOG(ERROR) << "Failed to listen!";
        return false;
    }
    m_event_dispatch_thread = std::thread(&management_client::event_dispatch, this);
    return true;
}

void management_client::event_dispatch()
{
    imif::messages::mgmt_ext::Event event;
    void *got_tag;
    bool ok = false;
    m_running.store(true);

    while (m_running.load()) {
        if (!m_cq->Next(&got_tag, &ok)) {
            LOG(ERROR) << "Completion queue shutting down";
            break;
        }
        if (ok) {
            m_event_reader->Read(&event, got_tag);
            if (!event.message().empty()) {
                if (m_listener_callback) {
                    m_listener_callback(event);
                }
            }
        } else {
            LOG(INFO) << "Disconnected from server!";
            break;
        }
    }
    m_running.store(false);
}
void management_client::register_listener_callback(CallbackFunc callback) { m_listener_callback = callback; }

bool management_client::check_error(grpc::Status &status)
{
    if (!status.ok()) {
        LOG(ERROR) << "RPC failed: " << status.error_message();
        LOG(ERROR) << "Details: " << status.error_details();
        return false;
    }
    return true;
}

int64_t management_client::add_workgroup(std::string &host_or_ip_str, uint32_t port, std::string wgname)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }
    imif::messages::mgmt_ext::AddWorkgroup add_workgroup;
    add_workgroup.set_url(host_or_ip_str);
    add_workgroup.set_port(port);

    imif::messages::mgmt_ext::WorkgroupID workgroup_id;
    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->AddWorkgroup(&context, add_workgroup, &workgroup_id);

    if (!check_error(status)) {
        return false;
    }
    if (wgname != "") {
        set_workgroup_name(workgroup_id.wgid(), wgname);
    }

    return workgroup_id.wgid();
}

bool management_client::set_workgroup_name(int64_t wgid, std::string wgname)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }
    imif::messages::mgmt_ext::NameWorkgroup name_workgroup;
    name_workgroup.set_wgid(wgid);
    name_workgroup.set_wgname(wgname);

    imif::messages::mgmt_ext::ReturnStatus ret;
    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->NameWorkgroup(&context, name_workgroup, &ret);

    if (!check_error(status)) {
        return false;
    }
    return ret.success();
}

int64_t management_client::get_workgroup_id(std::string wgname)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }
    imif::messages::mgmt_ext::NameWorkgroup get_workgroup_id;
    get_workgroup_id.set_wgname(wgname);

    imif::messages::mgmt_ext::WorkgroupID workgroup_id;
    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->GetWorkgroupID(&context, get_workgroup_id, &workgroup_id);

    if (!check_error(status)) {
        return false;
    }

    return workgroup_id.wgid();
}

bool management_client::add_source(const imif::messages::types::Source &source, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::SourceAdd source_add;
    source_add.mutable_source()->CopyFrom(source);
    source_add.set_wgid(wgid);

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->SourceAdd(&context, source_add, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }

    return mgmtReturnStatus.success();
}

bool management_client::remove_source(uint32_t source_id, int64_t wgid) { return remove_item(source_id, "source", "", wgid); }

bool management_client::remove_config(uint32_t cfg_id, std::string module_name, int64_t wgid)
{
    return remove_item(cfg_id, "config", module_name, wgid);
}

bool management_client::remove_item(uint32_t item_id, std::string item_name, std::string module_name, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::RemoveItem remove_item;
    remove_item.set_id(item_id);
    remove_item.set_item_name(item_name);
    remove_item.set_module_name(module_name);
    remove_item.set_wgid(wgid);
    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->Remove(&context, remove_item, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }
    return mgmtReturnStatus.success();
}

bool management_client::add_flow(imif::messages::types::Flow &flow, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::FlowAdd flow_add;
    flow_add.mutable_flow()->CopyFrom(flow);
    flow_add.set_wgid(wgid);

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->FlowAdd(&context, flow_add, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }

    return mgmtReturnStatus.success();
}

bool management_client::remove_flow(uint32_t flow_id, int64_t wgid) { return remove_item(flow_id, "flow", "", wgid); }

bool management_client::add_config(imif::messages::mgmt::AddConfig &add_config, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;
    add_config.set_wgid(wgid);

    grpc::ClientContext context;
    grpc::Status status;
    status = m_stub->AddConfig(&context, add_config, &mgmtReturnStatus);
    if (!check_error(status)) {
        return false;
    }

    return mgmtReturnStatus.success();
}

bool management_client::set_log_level(std::string module_name, imif::common::eLogLevel log_lvl, bool new_state)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return true;
    }

    messages::mgmt_ext::SetLogLevel request;

    request.set_module_name(module_name);
    request.set_new_state(new_state);
    request.set_log_level((uint32_t)log_lvl);

    // send request via grpc.
    grpc::ClientContext context;
    grpc::Status status;
    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    status = m_stub->LogLevelSet(&context, request, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }
    return mgmtReturnStatus.success();
}

bool management_client::start_source(uint32_t source_id, int64_t wgid)
{
    messages::mgmt::StartSource start_source;
    start_source.set_source_id(source_id);
    start_source.set_wgid(wgid);

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->SourceStart(&context, start_source, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }

    return mgmtReturnStatus.success();
}

bool management_client::load_yaml(std::string conf_file, int64_t wgid)
{
    yaml_node yaml_config = yaml_builder::parse_file(conf_file);
    if (!yaml_config) {
        LOG(ERROR) << "YAML::LoadFile() failed";
        return false;
    }
    bool return_value = true;
    return_value = return_value && mstream_add_config(yaml_config, wgid);
    return_value = return_value && mdecode_add_config(yaml_config, wgid);
    return_value = return_value && inference_add_config(yaml_config, wgid);
    return_value = return_value && custom_add_config(yaml_config, wgid);
    return_value = return_value && add_source(yaml_config, wgid);
    return_value = return_value && add_flow(yaml_config, wgid);
    return return_value;
}

bool management_client::mstream_add_config(yaml_node &yaml_config, int64_t wgid)
{
    auto module_yaml = yaml_config["mstream"];
    if (!module_yaml) {
        LOG(INFO) << "No mstream in the yaml";
        return true;
    }

    auto optional_yaml = module_yaml["optional"];
    if (optional_yaml) {
        messages::mgmt::GlobalConfig globalConfig;
        globalConfig.set_module_name("mstream");
        globalConfig.set_log_level(optional_yaml["log_level"].scalar());
        globalConfig.set_dump_path(optional_yaml["dump_path"].scalar());
        messages::mgmt::AddConfig add_global_config;
        add_global_config.set_module_name("global");
        add_global_config.mutable_config()->mutable_config()->PackFrom(globalConfig);
        add_config(add_global_config, wgid);
    }

    auto configs_yaml = module_yaml["config"];
    if (!configs_yaml) {
        LOG(ERROR) << "No configs for mstream in the yaml";
        return false;
    }

    for (auto config_yaml_it : configs_yaml) {
        auto config_yaml = *config_yaml_it;
        messages::mstream::Config mstConfig;

        std::string val = config_yaml["id"].scalar();
        if (val.empty()) {
            LOG(ERROR) << " no id for config. node: " << config_yaml;
            continue;
        }
        uint32_t config_id;
        try {
            config_id = common::string_utils::stou(val);
        } catch (std::exception e) {
            LOG(ERROR) << "Invalid config id: " << val << ". " << e.what();
            continue;
        }
        val = config_yaml["stream_type"].scalar();
        if (val.empty()) {
            LOG(ERROR) << "no stream_type for config. node: " << config_yaml;
            continue;
        } else if (val == "rtsp") {
            mstConfig.set_type(messages::enums::StreamType::RTSP);
        } else if (val == "grpc") {
            mstConfig.set_type(messages::enums::StreamType::IMIF_SL);
        } else if (val == "file") {
            mstConfig.set_type(messages::enums::StreamType::LOCAL_FILE);
        }

        val = config_yaml["listening_port"].scalar();
        if (val.empty())
            val = "0";
        mstConfig.set_listening_ip_port(val);

        auto optional_yaml = config_yaml["optional"];
        if (optional_yaml) {
            messages::mstream::OptionalConfig mstOptionalConfig;

            val = optional_yaml["batch_size"].scalar();
            if (val.empty())
                val = "2";
            try {
                mstOptionalConfig.set_batch_size(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid batch_size " << val << " " << e.what();
                continue;
            }

            mstConfig.mutable_optional_config()->PackFrom(mstOptionalConfig);
        }

        messages::mgmt::AddConfig mgmtConfig;
        mgmtConfig.set_module_name("mstream");
        mgmtConfig.mutable_config()->set_id(config_id);
        mgmtConfig.mutable_config()->set_name(config_yaml["name"].scalar());
        mgmtConfig.mutable_config()->mutable_config()->PackFrom(mstConfig);

        add_config(mgmtConfig, wgid);
    }

    return true;
}

bool management_client::mdecode_add_config(yaml_node &yaml_config, int64_t wgid)
{
    auto module_yaml = yaml_config["mdecode"];
    if (!module_yaml) {
        LOG(INFO) << "No mdecode in the yaml";
        return true;
    }

    auto optional_yaml = module_yaml["optional"];
    if (optional_yaml) {
        messages::mgmt::GlobalConfig globalConfig;
        globalConfig.set_module_name("mdecode");
        globalConfig.set_log_level(optional_yaml["log_level"].scalar());
        globalConfig.set_dump_path(optional_yaml["dump_path"].scalar());

        messages::mdecode::GlobalConfig gvdGlobal;

        std::string val = optional_yaml["error_report"].scalar();
        bool value = false;
        if (val == "True") {
            value = true;
        }
        gvdGlobal.set_error_report(value);

        globalConfig.mutable_optional_config()->PackFrom(gvdGlobal);

        messages::mgmt::AddConfig add_global_config;
        add_global_config.set_module_name("global");
        add_global_config.mutable_config()->mutable_config()->PackFrom(globalConfig);
        add_config(add_global_config, wgid);
    }

    auto configs_yaml = module_yaml["config"];
    if (!configs_yaml) {
        LOG(ERROR) << "No configs for mdecode in the yaml";
        return false;
    }

    for (auto config_yaml_it : configs_yaml) {
        auto config_yaml = *config_yaml_it;
        messages::mdecode::Config gvdConfig;

        std::string val = config_yaml["id"].scalar();
        if (val.empty()) {
            LOG(ERROR) << " no id for config. node:" << config_yaml;
            continue;
        }
        uint32_t config_id;
        try {
            config_id = common::string_utils::stou(val);
        } catch (std::exception e) {
            LOG(ERROR) << "invalid config_id " << val << ". " << e.what();
            continue;
        }

        val = config_yaml["video_type"].scalar();
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        if (val != "h264" && val != "h265" && val != "jpeg" && val != "mjpeg" && val != "jpg") {
            LOG(ERROR) << "Invalid video type " << val;
            continue;
        }
        gvdConfig.set_video_type(val);

        val = config_yaml["output_format"].scalar();
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        if (val != "nv12" && val != "i420" && val != "rgb4") {
            LOG(ERROR) << "Invalid output_format " << val;
            continue;
        }
        gvdConfig.set_output_format(val);

        std::vector<std::string> out_vec;
        get_string_sequence(config_yaml, "inline_scale", out_vec);
        if (out_vec.size() != 2) {
            out_vec.push_back("0");
            out_vec.push_back("0");
        }
        try {
            gvdConfig.set_inline_scale_width(common::string_utils::stou(out_vec.at(0)));
            gvdConfig.set_inline_scale_height(common::string_utils::stou(out_vec.at(1)));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid scaling parameters " << out_vec << ". " << e.what();
            continue;
        }

        val = config_yaml["threads_num"].scalar();
        if (val.empty())
            val = "2";
        try {
            gvdConfig.set_threads_num(common::string_utils::stou(val));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid thread number " << val << ". " << e.what();
            continue;
        }

        val = config_yaml["complete_frame"].scalar();
        bool value = false;
        if (common::string_utils::caseless_eq(val, "true") || val == "1") {
            value = true;
        } 
        gvdConfig.set_complete_frame(value);

        val = config_yaml["hw_device_num"].scalar();
        if (val.empty())
            val = "0";
        try {
            gvdConfig.set_hw_device_num(std::stoi(val));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid hw_device_num " << val << ". " << e.what();
            continue;
        }

        auto optional_yaml = config_yaml["optional"];
        if (optional_yaml) {
            messages::mdecode::OptionalConfig gvdOptionalConfig;

            val = optional_yaml["gen_postproc"].scalar();
            if (val.empty())
                val = "0";
            try{
                gvdOptionalConfig.set_gen_postproc(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid gen_postproc " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["async_depth"].scalar();
            if (val.empty())
                val = "4";
            try{
                gvdOptionalConfig.set_async_depth(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid async_depth " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["batch_size"].scalar();
            if (val.empty())
                val = "1";
            try{
                gvdOptionalConfig.set_batch_size(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid batch_size " << val << ". " << e.what();
                continue;
            }

            gvdConfig.mutable_optional_config()->PackFrom(gvdOptionalConfig);
        }

        messages::mgmt::AddConfig mgmtConfig;
        mgmtConfig.set_module_name("mdecode");
        mgmtConfig.mutable_config()->set_id(config_id);
        mgmtConfig.mutable_config()->set_name(config_yaml["name"].scalar());
        mgmtConfig.mutable_config()->mutable_config()->PackFrom(gvdConfig);

        add_config(mgmtConfig, wgid);
    }

    return true;
}

bool management_client::custom_add_config(yaml_node &yaml_config, int64_t wgid)
{
    auto custom_yaml = yaml_config["custom"];
    if (!custom_yaml) {
        LOG(INFO) << "No custom in the yaml";
        return true;
    }

    for (auto module_yaml_it : custom_yaml) {
        auto module_yaml = *module_yaml_it;
        auto module_name = module_yaml["module_name"].scalar();
        if (module_name.empty()) {
            LOG(ERROR) << "custom YAML doesn't contain module name!";
            continue;
        }

        auto configs_yaml = module_yaml["config"];
        if (!configs_yaml) {
            LOG(INFO) << "No configs for module_name in the yaml";
            continue;
        }

        for (auto config_yaml_it : configs_yaml) {
            auto config_yaml = *config_yaml_it;
            messages::mgmt::AddConfig mgmt_config;
            mgmt_config.set_module_name(module_name);

            std::string val = config_yaml["id"].scalar();
            if (val.empty()) {
                LOG(ERROR) << " no id for config " << config_yaml;
                continue;
            }

            uint32_t config_id;
            try {
                config_id = common::string_utils::stou(val);
            } catch (std::exception e) {
                LOG(ERROR) << "invalid config_id " << val << ". " << e.what();
                continue;
            }
            mgmt_config.mutable_config()->set_id(config_id);
            mgmt_config.mutable_config()->set_name(config_yaml["name"].scalar());

            config_yaml.remove("id");
            config_yaml.remove("name");

            messages::types::CustomConfig custom_config;
            for (auto pair = config_yaml.map_begin(); pair != config_yaml.map_end(); pair++) {
                std::string key = pair->first;
                ;
                std::string value = pair->second->scalar();
                (*custom_config.mutable_config_map())[key] = value;
            }

            mgmt_config.mutable_config()->mutable_config()->PackFrom(custom_config);

            add_config(mgmt_config, wgid);
        }
    }

    return true;
}

bool management_client::inference_add_config(imif_yaml::yaml_node &yaml_config, int64_t wgid)
{
    auto module_yaml = yaml_config["inference"];
    if (!module_yaml) {
        LOG(INFO) << "No inference in the yaml";
        return true;
    }

    auto optional_yaml = module_yaml["optional"];
    if (optional_yaml) {
        messages::mgmt::GlobalConfig globalConfig;
        globalConfig.set_module_name("inference");
        globalConfig.set_log_level(optional_yaml["log_level"].scalar());
        globalConfig.set_dump_path(optional_yaml["dump_path"].scalar());

        messages::inference::GlobalConfig ilbGlobal;
        auto ignore_flows = optional_yaml["ignore_flows"];
        for (auto flow : ignore_flows) {
            try {
                ilbGlobal.add_ignore_flows(common::string_utils::stou(flow->scalar()));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid flow in ignore_flows" << flow->scalar() << ". " << e.what();
                continue;
            }
        }

        ilbGlobal.set_collect_blob_results_path(optional_yaml["collect_blob_results_path"].scalar());
        ilbGlobal.set_collect_yaml_results_path(optional_yaml["collect_yaml_results_path"].scalar());

        ilbGlobal.set_collect_stats_path(optional_yaml["collect_stats_path"].scalar());

        std::string stats_frames_str = optional_yaml["collect_stats_frames"].scalar();
        if (stats_frames_str.empty())
            stats_frames_str = "0";
        try {
            ilbGlobal.set_collect_stats_frames(common::string_utils::stou(stats_frames_str));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid collect_stats_frames " << stats_frames_str << ". " << e.what();
        }

        std::string val = optional_yaml["output_rate_control"].scalar();
        if (val.empty())
            val = "0";
        try {
            ilbGlobal.set_output_rate_control(bool(common::string_utils::stou(val)));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid rate_control " << val << ". " << e.what();
        }

        globalConfig.mutable_optional_config()->PackFrom(ilbGlobal);

        messages::mgmt::AddConfig add_global_config;
        add_global_config.set_module_name("global");
        add_global_config.mutable_config()->mutable_config()->PackFrom(globalConfig);
        add_config(add_global_config, wgid);
    }

    auto configs_yaml = module_yaml["config"];
    if (!configs_yaml) {
        LOG(ERROR) << "No configs for inference in the yaml";
        return false;
    }

    for (auto config_yaml_it : configs_yaml) {
        auto config_yaml = *config_yaml_it;
        messages::inference::Config ilbConfig;

        std::string val = config_yaml["id"].scalar();
        if (val.empty()) {
            LOG(ERROR) << " no id for config " << config_yaml;
            continue;
        }
        uint32_t config_id;
        try {
            config_id = common::string_utils::stou(val);
        } catch (std::exception e) {
            LOG(ERROR) << "invalid config_id " << val << ". " << e.what();
            continue;
        }

        val = config_yaml["hw_device_num"].scalar();
        if (val.empty())
            val = "0";
        try {
            ilbConfig.set_hw_device_num(std::stoi(val));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid hw_device_num " << val << ". " << e.what();
            continue;
        }

        val = config_yaml["model_type"].scalar();
        if (val.empty())
            val = "resnet50";
        ilbConfig.set_model_type(val);

        val = config_yaml["engine_type"].scalar();
        if (val.empty())
            val = "openvino";
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        if (val != "openvino") {
            LOG(ERROR) << "Invalid engine type " << val;
            continue;
        }
        ilbConfig.set_engine_type(val);

        val = config_yaml["engine_device"].scalar();
        if (val.empty())
            val = "CPU";
        ilbConfig.set_engine_device(val);

        val = config_yaml["num_of_inference_requests"].scalar();
        if (val.empty())
            val = "10";
        uint32_t num_of_inference_requests;
        try {
            num_of_inference_requests = common::string_utils::stou(val);
        } catch (std::exception e) {
            LOG(ERROR) << "invalid num_of_inference_requests " << val << ". " << e.what();
            continue;
        }
        ilbConfig.set_num_of_inference_requests(num_of_inference_requests);

        val = config_yaml["batch_size"].scalar();
        if (val.empty())
            val = "1";
        uint32_t batch_size;
        try {
            batch_size = common::string_utils::stou(val);
        } catch (std::exception e) {
            LOG(ERROR) << "invalid batch_size " << val << ". " << e.what();
            continue;
        }
        ilbConfig.set_batch_size(batch_size);

        val = config_yaml["model_path"].scalar();
        ilbConfig.set_model_path(val);

        val = config_yaml["inference_input_precision"].scalar();
        if (val.empty())
            val = "uint8";
        ilbConfig.set_inference_input_precision(val);

        val = config_yaml["inference_rate"].scalar();
        if (val.empty())
            val = "0"; // 0 means automatic control, -1 means no limit
        try {
            ilbConfig.set_inference_rate(std::stoi(val));
        } catch (std::exception e) {
            LOG(ERROR) << "invalid inference_rate " << val << ". " << e.what();
            continue;
        }

        auto optional_yaml = config_yaml["optional"];
        if (optional_yaml) {
            messages::inference::OptionalConfig ilbOptionalConfig;

            val = optional_yaml["openvino_n_threads"].scalar();
            if (val.empty())
                val = "1";
            uint32_t openvino_n_threads;
            try {
                openvino_n_threads = common::string_utils::stou(val);
            } catch (std::exception e) {
                LOG(ERROR) << "invalid openvino_n_threads " << val << ". " << e.what();
                continue;
            }
            ilbOptionalConfig.set_openvino_n_threads(openvino_n_threads);

            val = optional_yaml["result_processing_plugin"].scalar();
            ilbOptionalConfig.set_result_processing_plugin(val);

            val = optional_yaml["detection_threshold"].scalar();
            double threshold;
            try {
                threshold = std::stof(val);
            } catch (std::exception e) {
                LOG(ERROR) << "invalid threshold " << val << ". " << e.what();
                continue;
            }
            if (threshold < 0 || threshold > 1) {
                LOG(ERROR) << "Invalid detection threshold " << val;
                continue;
            }
            ilbOptionalConfig.set_detection_threshold(threshold);

            val = optional_yaml["labels_file"].scalar();
            ilbOptionalConfig.set_labels_file(val);

            val = optional_yaml["ssd_boxes_file"].scalar();
            ilbOptionalConfig.set_ssd_boxes_file(val);

            val = optional_yaml["max_num_of_bounding_boxes"].scalar();
            if (!val.empty()) {
                try {
                    ilbOptionalConfig.set_max_num_of_bounding_boxes(common::string_utils::stou(val));
                } catch (std::exception e) {
                    LOG(ERROR) << "invalid num_of_bounding_boxes " << val << ". " << e.what();
                    continue;
                }
            }

            val = optional_yaml["hetero_dump_graph_dot"].scalar();
            bool value = ((val == "True") || (val == "true"));
            ilbOptionalConfig.set_hetero_dump_graph_dot(value);

            ilbConfig.mutable_optional_config()->PackFrom(ilbOptionalConfig);
            val = optional_yaml["always_send_results"].scalar();
            value = ((val != "False") && (val != "false")); // default is true;
            ilbOptionalConfig.set_always_send_results(value);
        }

        messages::mgmt::AddConfig mgmtConfig;
        mgmtConfig.set_module_name("inference");
        mgmtConfig.mutable_config()->set_id(config_id);
        mgmtConfig.mutable_config()->set_name(config_yaml["name"].scalar());
        mgmtConfig.mutable_config()->mutable_config()->PackFrom(ilbConfig);

        add_config(mgmtConfig, wgid);

        //sph-d workaround
        //std::this_thread::sleep_for(std::chrono::milliseconds(500)); //adding a delay to avoid mishaps using more than one inference devices
    }

    return true;
}

bool management_client::add_source(imif_yaml::yaml_node &yaml_config, int64_t wgid)
{
    auto source_yaml = yaml_config["source"];
    if (!source_yaml) {
        LOG(INFO) << "No sources in the file";
        return true;
    }

    auto config_yaml = source_yaml["config"];
    if (!config_yaml) {
        LOG(ERROR) << "No configs for inference in the yaml";
        return false;
    }

    for (auto yaml_source_it : config_yaml) {
        auto yaml_source = *yaml_source_it;
        messages::types::Source source;
        std::string val;

        auto source_id_seq = yaml_source["id"];
        uint32_t min_id, max_id;
        switch (source_id_seq.size()) {
        case 1: {
            try {
                min_id = max_id = common::string_utils::stou(source_id_seq[0].scalar());
            } catch (std::exception e) {
                LOG(ERROR) << "invalid source_id_seq " << source_id_seq[0].scalar() << ". " << e.what();
                continue;
            }
            break;
        }
        case 2: {
            try {
                min_id = common::string_utils::stou(source_id_seq[0].scalar());
                max_id = common::string_utils::stou(source_id_seq[1].scalar());
            } catch (std::exception e) {
                LOG(ERROR) << "invalid source_id_seq " << source_id_seq[0].scalar() << ". " << e.what();
                LOG(ERROR) << "invalid source_id_seq " << source_id_seq[1].scalar();
                continue;
            }
            if (min_id > max_id) {
                LOG(ERROR) << "Invalid source - id field is wrong: Max value smaller than min value: " << yaml_source;
                continue;
            }
            break;
        }
        default: {
            LOG(ERROR) << "Invalid source - id field is wrong, node: " << yaml_source;
            continue;
        }
        }

        val = yaml_source["name"].scalar();
        source.set_name(val);

        val = yaml_source["type"].scalar();
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        if (val == "rtsp") {
            source.set_type(::imif::messages::enums::StreamType::RTSP);
        } else if (val == "file") {
            source.set_type(::imif::messages::enums::StreamType::LOCAL_FILE);
        } else if ((val == "imif_sl") || (val == "grpc")) {
            source.set_type(::imif::messages::enums::StreamType::IMIF_SL);
        } else {
            source.set_type(::imif::messages::enums::StreamType::STREAM_TYPE_INVALID);
            LOG(ERROR) << "Invalid source - STREAM_TYPE_INVALID. node: " << yaml_source;
            continue;
        }

        std::vector<std::string> input_list;
        get_string_sequence(yaml_source, "input", input_list);
        if (source.type() == ::imif::messages::enums::StreamType::IMIF_SL) {
            if (input_list.size() > 0) {
                LOG(ERROR) << "'input' not supported for GRPC";
                continue;
            }
            input_list.emplace_back("");
        } else {
            if (input_list.size() == 0) {
                LOG(INFO) << "can't read 'input' configuration";
                continue;
            }

            prep_rtsp_url_list(input_list);

            if (input_list.size() != (max_id - min_id + 1)) {
                LOG(ERROR) << "Input list size doesn't match the input list size";
                continue;
            }
        }

        // add optional part
        auto optional_yaml = yaml_source["optional"];
        if (optional_yaml) {
            messages::types::OptionalSource optionalSource;

            val = optional_yaml["fps"].scalar();
            if (val.empty())
                val = "0";
            try {
                optionalSource.set_fps(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid fps " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["mbps"].scalar();
            if (val.empty())
                val = "0";
            try {
                optionalSource.set_mbps(std::stof(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid mbps " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["duplicate_input_files"].scalar();
            if (val.empty())
                val = "0";
            try {
                optionalSource.set_duplicate_input_files(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid duplicate_input_files " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["width"].scalar();
            if (val.empty())
                val = "0";
            try {
                optionalSource.set_input_width(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid width " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["height"].scalar();
            if (val.empty())
                val = "0";
            try {
                optionalSource.set_input_height(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid height " << val << ". " << e.what();
                continue;
            }

            val = optional_yaml["load_to_ram"].scalar();
            bool load_to_ram = false;
            if (!val.empty()) {
                if ((val == "1") || (val == "true") || (val == "True")) {
                    load_to_ram = true;
                }
            }
            optionalSource.set_load_to_ram(load_to_ram);

            val = optional_yaml["ram_size_mb"].scalar();
            if (val.empty())
                val = "512";
            try {
                optionalSource.set_ram_size_mb(common::string_utils::stou(val));
            } catch (std::exception e) {
                LOG(ERROR) << "invalid ram_size_mb " << val << ". " << e.what();
                continue;
            }

            source.mutable_additional_info()->PackFrom(optionalSource);
        }

        uint32_t input_id = 0;
        for (uint32_t id = min_id; id <= max_id; ++id) {
            source.set_id(id);
            source.set_input(input_list[input_id++]);
            add_source(source, wgid);
        }
    }

    return true;
}

bool management_client::add_flow(yaml_node &yaml_config, int64_t wgid)
{
    auto flows = yaml_config["flows"];
    if (!flows) {
        LOG(INFO) << "No flows in the file";
        return true;
    }

    for (auto yaml_flow_it : flows) {
        auto yaml_flow = *yaml_flow_it;
        messages::types::Flow flow;
        std::string val;

        std::vector<std::string> flow_id_vec;
        get_string_sequence(yaml_flow, "id", flow_id_vec);
        if (flow_id_vec.size() == 0 || flow_id_vec.size() > 2) {
            LOG(ERROR) << "Invalid flow - id field is wrong. node: " << yaml_flow;
            continue;
        }

        std::vector<std::string> source_id_vec;
        get_string_sequence(yaml_flow, "source", source_id_vec);
        if (source_id_vec.size() > 2) {
            LOG(ERROR) << "Invalid flow - source field is wrong. node: " << yaml_flow;
            continue;
        }

        val = yaml_flow["name"].scalar();
        flow.set_name(val);

        auto yaml_pipeline = yaml_flow["pipeline"];
        if (!yaml_pipeline) {
            LOG(ERROR) << "Invalid flow - no pipeline field: " << yaml_flow;
            continue;
        }

        for (auto yaml_stage_it : yaml_pipeline) {
            auto yaml_stage = *yaml_stage_it;
            if (yaml_stage.size() > 3) {
                LOG(ERROR) << "Invalid stage - too many elements";
                return false;
            }

            auto stage = flow.mutable_pipeline()->add_stage();

            for (auto pair = yaml_stage.map_begin(); pair != yaml_stage.map_end(); ++pair) {
                std::string key = pair->first;

                if (key == "stage") {
                    try {
                        stage->set_id(common::string_utils::stou(pair->second->scalar()));
                    } catch (std::exception e) {
                        LOG(ERROR) << "invalid stage_id " << pair->second->scalar() << ". " << e.what();
                        continue;
                    }
                } else if (key == "next_stage") {
                    std::vector<std::string> next_stages;
                    get_string_sequence(yaml_stage, key, next_stages);
                    for (const auto &next_stage : next_stages) {
                        try {
                            stage->add_next_stage(common::string_utils::stou(next_stage));
                        } catch (std::exception e) {
                            LOG(ERROR) << "invalid stage_id " << next_stage << ". " << e.what();
                            continue;
                        }
                    }
                } else {
                    stage->set_module_name(key);
                    std::string config_identifier = pair->second->scalar();
                    if (::isdigit(config_identifier[0])) {
                        try {
                            stage->set_config_id(common::string_utils::stou(config_identifier));
                        } catch (std::exception e) {
                            LOG(ERROR) << "invalid config_identifier " << config_identifier << ". " << e.what();
                            continue;
                        }
                    } else {
                        stage->set_config_name(config_identifier);
                    }
                }
            }
        }

        uint32_t flow_id;
        uint32_t last_flow_id;
        int32_t last_source_id;
        try{
            flow_id = common::string_utils::stou(flow_id_vec.front());
            last_flow_id = common::string_utils::stou(flow_id_vec.back());
            last_source_id = std::stoi(source_id_vec.back());
        } catch (std::exception e) {
            LOG(ERROR) << e.what();
            return false;
        }
        int32_t source_id = -1;
        if (source_id_vec.size() == 2) {
            if (flow_id_vec.size() < 2) {
                LOG(ERROR) << "Flow_ids (" << flow_id_vec << ") do not corresspond to source_ids (" << source_id_vec << ")";
                return false;
            }
            try {
                source_id = common::string_utils::stou(source_id_vec.front());
            } catch (std::exception e) {
                LOG(ERROR) << e.what();
                return false;
            }

            if ((last_source_id - source_id) - (last_flow_id - flow_id) != 0) {
                LOG(ERROR) << "Flow_ids (" << flow_id_vec << ") do not correspond to source_ids (" << source_id_vec << ")";
                return false;
            }
        } else if (source_id_vec.size() == 1) {
            if (source_id_vec[0] != "None")
                try {
                    source_id = common::string_utils::stou(source_id_vec.front());
                } catch (std::exception e) {
                    LOG(ERROR) << e.what();
                    return false;
                }
        }

        for (; flow_id <= last_flow_id; flow_id++) {
            flow.set_id(flow_id);
            if (source_id != -1) {
                flow.set_source_id(source_id);
                if (source_id < last_source_id)
                    source_id++;
            }
            add_flow(flow, wgid);
        }
    }

    return true;
}

bool management_client::command(const messages::types::Command &command, int64_t wgid)
{
    if (!m_stub) {
        LOG(INFO) << "Not connected";
        return false;
    }

    messages::mgmt::Command mgmt_command;
    mgmt_command.mutable_command()->CopyFrom(command);
    mgmt_command.set_wgid(wgid);

    imif::messages::mgmt_ext::ReturnStatus mgmtReturnStatus;

    grpc::ClientContext context;
    grpc::Status status;

    status = m_stub->RequestCommand(&context, mgmt_command, &mgmtReturnStatus);

    if (!check_error(status)) {
        return false;
    }

    return mgmtReturnStatus.success();
}
