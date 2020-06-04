
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

#include <dirent.h>

#include "easylogging++.h"

#include "common_defines.h"
#include "common_message.h"
#include "common_os_utils.h"
#include "common_string_utils.h"
#include "management_server.h"
#include "mgmt_thread.h"

#include <messages/proto/enums.pb.h>
#include <messages/proto/inference.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>

using namespace imif;
using namespace common;
using namespace mgmt;

#define SELECT_TIMEOUT_MSEC 200

MgmtThread::MgmtThread(std::string &broker_path, std::shared_ptr<common::Socket> ui_socket, imif::common::logging *pLogger)
    : broker_thread("MgmThread"), m_module_name("mgmt"), m_ui_socket(ui_socket), m_pLogger(pLogger)
{
    set_select_timeout(SELECT_TIMEOUT_MSEC);
}

MgmtThread::~MgmtThread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void MgmtThread::reset() { LOG(INFO) << "reset()"; }

void MgmtThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    reset();
}

bool MgmtThread::post_init()
{
    if (!add_socket(m_ui_socket)) {
        LOG(ERROR) << "Failed to add socket";
        return false;
    }

    add_workgroup("127.0.0.1", messages::enums::TCP_BROKER_PORT);

    return true;
}

bool MgmtThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    auto wgid_it = m_socket2wgid.find(sd->getSocketFd());
    if (wgid_it == m_socket2wgid.end()) {
        LOG(ERROR) << "got msg from unknown socket";
        return false;
    }
    auto wgid = wgid_it->second;
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "got msg from known socket, but have no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    switch (opcode) {
    case messages::enums::Opcode::MGMT_REGISTER_REQUEST: {
        messages::mgmt::RegisterRequest request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing MgmtRegisterRequest";
            return false;
        }

        LOG(DEBUG) << "Recieved MGMT_REGISTER_REQUEST: " << request;
        auto module_name = request.module_name();
        std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);

        auto &member = wg.pipe_members[module_name];
        if (member.registered) {
            LOG(WARNING) << "Module with name " << request.module_name() << " was already registered with id "
                         << member.assigned_id;
        } else {
            member.assigned_id = wg.next_module_id++;
        }

        member.registered = true;

        messages::mgmt::RegisterResponse response;
        response.set_module_id(member.assigned_id);
        response.set_module_name(request.module_name());

        if (!send_msg(sd, messages::enums::Opcode::MGMT_REGISTER_RESPONSE, response)) {
            LOG(ERROR) << "Failed sending MGMT_REGISTER_RESPONSE " << request;
            return false;
        }

    } break;
    case messages::enums::Opcode::MGMT_EVENT_STAT_READY: {
        messages::mgmt::Statistics statistic;
        if (!statistic.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Statistics";
            return false;
        }

        auto topic = statistic.topic();
        m_stat_topics.insert({topic, wgid});
        LOG(DEBUG) << "Got stats. Topic " << topic << ": " << statistic.stat();
        m_workgroups[wgid].publisher_.publish(topic, statistic.stat());
    } break;
    case messages::enums::INFERENCE_RESULTS_READY: {
        messages::types::EventResultReady results;
        if (!results.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing result";
            return false;
        }

        for (auto result : results.results()) {
            auto frame_info = result.frame_info();
            auto flow_id = frame_info.flow().id();
            auto stage = frame_info.flow().stage_id(0);
            std::ostringstream stream;
            stream << "### irp result, flow_id " << flow_id << ", stage_id " << stage << ", frame "
                   << frame_info.frame().frame_num() << ", client context " << frame_info.frame().client_context();
            for (auto &object : result.detected_object()) {
                stream << " label: " << object.label();
                stream << " probability: " << object.probability();
            }

            std::string result_string = stream.str();

            LOG(DEBUG) << result_string;

            auto wgid_it = m_socket2wgid.find(sd->getSocketFd());
            if (wgid_it == m_socket2wgid.end()) {
                LOG(ERROR) << "got stat from unknown socket";
                return false;
            }
            auto wgid = wgid_it->second;
            m_workgroups[wgid].publisher_.publish("results", result_string);
        }

    } break;
    case messages::enums::Opcode::MGMT_PUSH_REQUEST: {
        messages::mgmt::SendChunk send_chunk;
        if (!send_chunk.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing sendFile";
            return false;
        }
        if (send_chunk.target_module() != m_module_name) {
            return true;
        }
        receive_logs(send_chunk);
        if (!send_chunk.is_last_chunk()) {
            send_msg(sd, messages::enums::Opcode::MGMT_PUSH_RESPONSE, send_chunk);
        }
        return true;
    } break;
    case messages::enums::Opcode::MGMT_PUSH_RESPONSE: {
        messages::mgmt::AckChunk ack;
        if (!ack.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing ack";
            return false;
        }
        acknowledge_push(ack);
        return true;
    } break;
    default: {
        LOG(ERROR) << "Unknown opcode " << int(opcode);
        return false;
    }
    }

    return true;
}

bool MgmtThread::handle_msg(std::shared_ptr<Socket> sd)
{
    void *tag;
    if (sd->getSocketFd() == m_ui_socket->getSocketFd()) {
        read(sd->getSocketFd(), &tag, sizeof(void *));

        base_call_data *call_data = base_call_data::validate_cast(tag);
        if (!call_data) {
            LOG(ERROR) << "Failed casting the tag!";
            return false;
        }

        call_data->process(this);
    } else {
        auto wgid_it = m_socket2wgid.find(sd->getSocketFd());
        if (wgid_it == m_socket2wgid.end()) {
            LOG(ERROR) << "got message from unrecognizd sd! " << sd->getSocketFd();
            return false;
        }
        messages::sProtoHeader header;
        int ret = read_proto_message(sd, header, m_rx_buffer, sizeof(m_rx_buffer));
        if (ret < 0) {
            LOG(ERROR) << "Failed reading and/or parsing message!";
            return false;
        } else if (ret == 0) {
            return true;
        }

        // Handle the incoming message
        if (!handle_msg(sd, messages::enums::Opcode(header.opcode), (header.length) ? m_rx_buffer : nullptr,
                        (header.length) ? header.length : 0)) {
            return false;
        }
        //LOG(ERROR) << "got event on unknown socket: " << sd;
    }
    return true;
}

bool MgmtThread::receive_logs(messages::mgmt::SendChunk &send_chunk)
{
    auto it = m_pull_responders.find(send_chunk.id());
    if (it == m_pull_responders.end()) {
        LOG(ERROR) << "Got file " << send_chunk.filename() << " with unrecognized id: " << send_chunk.id();
        return false;
    }
    auto &responder = it->second;
    if (send_chunk.is_last_chunk()) {
        responder->set_last_chunk();
    }
    responder->send_chunk(send_chunk.content());

    uint64_t length = send_chunk.content().size();
    send_chunk.clear_content();
    send_chunk.set_file_pos(send_chunk.file_pos() + length);
    if (send_chunk.is_last_chunk()) {
        m_pull_responders.erase(it);
    }
    return true;
}

bool MgmtThread::acknowledge_push(messages::mgmt::AckChunk &ack)
{
    auto it = m_push_responders.find(ack.id());
    if (it == m_push_responders.end()) {
        LOG(ERROR) << "Got ack with unrecognized id: " << ack.id();
        return false;
    }
    auto &responder = it->second;
    responder->set_success(ack.success());
    responder->process(this);
    if (ack.is_last_chunk() || !ack.success()) {
        m_push_responders.erase(it);
    }
    return true;
}

bool MgmtThread::socket_disconnected(std::shared_ptr<Socket> sd) { return true; }

bool MgmtThread::before_select() { return true; }

bool MgmtThread::enable_module(std::string module_name, bool enabled, std::string sub_module, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            enable_module(module_name, enabled, sub_module, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "asked to enable module for unrecognized wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;

    std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);
    auto it = wg.pipe_members.find(module_name);
    if (it == wg.pipe_members.end() && module_name != "all") {
        LOG(ERROR) << "tried to enable a module that doesn't exist: " << module_name;
        return false;
    }
    messages::mgmt::Enable enable_request;
    enable_request.set_module_name(module_name);
    enable_request.set_enable(enabled);
    enable_request.set_sub_module(sub_module);
    LOG(DEBUG) << "Sending MGMT_ENABLE: " << enable_request;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_ENABLE, enable_request)) {
        LOG(ERROR) << "Failed to send enable request message " << enable_request;
        return false;
    }
    if (module_name == "all") {
        for (auto &pipe_mem : wg.pipe_members) {
            pipe_mem.second.enabled = enabled;
        }
    } else {
        it->second.enabled = enabled;
    }
    return true;
}

void MgmtThread::list_modules(imif::messages::mgmt_ext::AllModulesStatus &output)
{
    for (auto &wg : m_workgroups) {
        for (auto &member : wg.second.pipe_members) {
            imif::messages::mgmt_ext::ModuleStatus *module_status = output.add_module_status();
            module_status->set_module_name(member.first);
            module_status->set_enabled(member.second.enabled);
            module_status->set_registered(member.second.registered);
            module_status->set_wgid(wg.first);
        }
    }
    for (auto &topic : m_stat_topics) {
        output.add_topic(topic.first);
    }
}

int64_t MgmtThread::add_workgroup(std::string url, int port)
{
    LOG(INFO) << "add_workgroup url " << url;
    auto sock = std::make_shared<SocketClient>(url, port, 2000);
    auto fd = sock->getSocketFd();
    if (fd < 0) {
        LOG(ERROR) << "Failed to connect to broker: " << url << ":" << port;
        return -1;
    }
    m_socket2wgid[fd] = m_next_wgid;
    auto &wg = m_workgroups[m_next_wgid];
    wg.broker_socket = sock;

    LOG(INFO) << "Added workgroup id " << m_next_wgid << " connected to " << url << ":" << port << " fd=" << fd;

    add_socket(sock);
    subscribe(sock, {messages::enums::MGMT_REGISTER_REQUEST, messages::enums::MGMT_EVENT_STAT_READY,
                     messages::enums::MGMT_PUSH_REQUEST, messages::enums::MGMT_PUSH_RESPONSE});
    m_id2wgname[m_next_wgid] = "";

    return m_next_wgid++;
}

bool MgmtThread::remove_workgroup(int64_t wgid)
{
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(WARNING) << "Asked to remove unrecognized workgroup: " << wgid;
        return false;
    }
    auto fd = wg_it->second.broker_socket->getSocketFd();
    m_socket2wgid.erase(fd);
    m_workgroups.erase(wg_it);
    return true;
}

int64_t MgmtThread::get_workgroup_id(std::string name)
{
    auto it = m_wgname2id.find(name);
    if (it == m_wgname2id.end()) {
        return -1;
    }
    return it->second;
}
bool MgmtThread::set_workgroup_name(int32_t wgid, std::string name)
{
    m_wgname2id[name] = wgid;
    m_id2wgname[wgid] = name;
    return true;
}

std::string MgmtThread::get_workgroup_name(int32_t wgid)
{
    auto it = m_id2wgname.find(wgid);
    if (it == m_id2wgname.end()) {
        return "";
    }
    return it->second;
}

bool MgmtThread::add_source(const imif::messages::types::Source &source, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            add_source(source, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "undefined wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    uint32_t id = source.id();
    if (wg.sources.find(id) != wg.sources.end()) {
        LOG(ERROR) << "Source id " << id << " already in use. Can't add source: " << source;
        return false;
    }
    wg.sources[id] = source;
    LOG(INFO) << "Added source: " << source;
    return true;
}

bool MgmtThread::start_source(uint32_t source_id, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            start_source(source_id, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "undefined wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    messages::mgmt::StartSource start_source;
    start_source.set_source_id(source_id);

    LOG(INFO) << "send MGMT_START_SOURCE: " << source_id;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_START_FLOW, start_source)) {
        LOG(ERROR) << "Failed sending message MGMT_START_SOURCE id=" << start_source.source_id();
    }

    return true;
}

bool MgmtThread::remove_source(uint32_t source_id, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            remove_source(source_id, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "got msg from known socket, but have no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    imif::messages::mgmt::RemoveSource source_remove;

    source_remove.set_source_id(source_id);
    LOG(INFO) << "send MGMT_REMOVE_SOURCE: " << source_id;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_REMOVE_SOURCE, source_remove)) {
        LOG(ERROR) << "Failed sending message MGMT_REMOVE_SOURCE id=" << source_remove.source_id();
    }
    wg.sources.erase(source_id);

    return true;
}

bool MgmtThread::remove_flow(uint32_t flow_id, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            remove_flow(flow_id, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "got msg from known socket, but have no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    imif::messages::mgmt::RemoveFlow flow_remove;
    flow_remove.set_flow_id(flow_id);
    LOG(INFO) << "send FLOW_REMOVE: " << flow_id;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_REMOVE_FLOW, flow_remove)) {
        LOG(ERROR) << "Failed sending message MGMT_REMOVE_FLOW flow=" << flow_id;
    }
    wg.flows.erase(flow_id);

    return true;
}

bool MgmtThread::remove_config(const messages::mgmt_ext::RemoveItem &remove_config_ext, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            remove_config(remove_config_ext, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;

    imif::messages::mgmt::RemoveConfig remove_config;
    auto cfg_id = remove_config_ext.id();
    auto cfg_module = remove_config_ext.module_name();
    // check if the config exists
    auto configs_it = wg.configs.find(cfg_module);
    if (configs_it == wg.configs.end()) {
        LOG(WARNING) << "Failed to remove config from unrecognized module: " << cfg_module;
        return false;
    }
    auto config_it = configs_it->second.find(cfg_id);
    if (config_it == configs_it->second.end()) {
        LOG(WARNING) << "Failed to remove config with unrecognized id: " << cfg_module << cfg_id;
        return false;
    }
    // check if the config is in use by any flow
    for (auto &flow_p : wg.flows) {
        messages::types::Flow flow = flow_p.second;
        for (auto &stage : flow.pipeline().stage()) {
            if (stage.config_id() == cfg_id && stage.config_name() == cfg_module) {
                LOG(WARNING) << "Cant remove config, as it is being used by flow " << flow << " at stage: " << stage.id();
                return false;
            }
        }
    }
    remove_config.set_config_id(cfg_id);
    remove_config.set_module_name(cfg_module);
    LOG(INFO) << "send CONFIG_REMOVE: " << remove_config;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_REMOVE_CONFIG, remove_config)) {
        LOG(ERROR) << "Failed sending message MGMT_REMOVE_CONFIG name=" << remove_config;
        return false;
    }

    configs_it->second.erase(config_it); // remove the config from wg.configs

    return true;
}

bool MgmtThread::add_flow(messages::types::Flow &flow, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            add_flow(flow, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;

    if (wg.flows.find(flow.id()) != wg.flows.end()) {
        LOG(ERROR) << "Cant add flow: " << flow << " Flow_id already in use by: " << wg.flows[flow.id()];
        return false;
    }

    uint32_t source_id = flow.source_id();
    if (wg.sources.find(source_id) == wg.sources.end()) {
        LOG(ERROR) << "Flow asked for an unrecognized source_id: " << flow;
        LOG(ERROR) << "offending source_id = " << source_id;
        return false;
    }
    //flow.pipeline().stage().at(0).has
    auto pipeline = flow.mutable_pipeline();
    for (auto &stage : *pipeline->mutable_stage()) {
        auto cfg_it = wg.configs.find(stage.module_name());
        if (cfg_it == wg.configs.end()) {
            LOG(ERROR) << "Unrecognized module_name on Flow : " << flow;
            LOG(ERROR) << "At stage: " << stage;
            return false;
        }
        auto cfg_map = cfg_it->second;
        uint32_t cfg_id;
        if (stage.config_case() == stage.kConfigId) {
            cfg_id = stage.config_id();
        } else {
            std::string cfg_name = stage.config_name();
            auto it = std::find_if(cfg_map.begin(), cfg_map.end(), [cfg_name](std::pair<uint32_t, messages::types::Config> conf) {
                return conf.second.name() == cfg_name;
            });
            cfg_id = it->second.id();
            stage.set_config_id(cfg_id);
        }
        if (cfg_map.find(cfg_id) == cfg_map.end()) {
            LOG(ERROR) << "Unrecognized configuration #" << cfg_id << " on Flow : " << flow;
            LOG(ERROR) << "At stage: " << stage;
            return false;
        }
    }

    wg.flows[flow.id()] = flow;

    messages::mgmt::AddSource add_source;
    add_source.mutable_source()->CopyFrom(wg.sources[source_id]);
    add_source.set_module_name(flow.pipeline().stage(0).module_name());

    LOG(INFO) << "MGMT_ADD_SOURCE: " << add_source;
    send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_ADD_SOURCE, add_source);

    messages::mgmt::AddFlow add_flow;
    add_flow.mutable_flow()->CopyFrom(flow);

    LOG(INFO) << "MGMT_ADD_FLOW: " << add_flow;
    send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_ADD_FLOW, add_flow);

    messages::mgmt::StartSource start_source;
    start_source.set_source_id(source_id);

    LOG(INFO) << "MGMT_START_FLOW: " << start_source;
    send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_START_FLOW, start_source);

    return true;
}

bool MgmtThread::request_command(messages::mgmt::Command &command, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            request_command(command, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;

    LOG(INFO) << "MGMT_CUSTOM_COMMAND: " << command;

    send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_CUSTOM_COMMAND, command);
    return true;
}

bool MgmtThread::add_config(imif::messages::mgmt::AddConfig &add_config_, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            add_config(add_config_, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "no wg defined for wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;

    LOG(INFO) << "MGMT_ADD_CONFIG: " << add_config_;

    std::string &module_name = *(add_config_.mutable_module_name());
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);

    if (wg.pipe_members.find(module_name) == wg.pipe_members.end() && module_name != "global") {
        LOG(ERROR) << "Invalid config: Unknown module name: " << module_name;
        return false;
    }
    if (module_name == "global") {
        messages::mgmt::GlobalConfig globalConfig;
        add_config_.config().config().UnpackTo(&globalConfig);
        send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_GLOBAL_CONFIG, globalConfig);
        return true;
    }
    uint32_t config_id = add_config_.config().id();
    if ((wg.configs.find(module_name) != wg.configs.end()) &&
        (wg.configs[module_name].find(config_id) != wg.configs[module_name].end())) {
        LOG(ERROR) << " id " << config_id << " already used for a " << module_name << " config.";
        return false;
    }
    wg.configs[module_name][config_id] = add_config_.config();
    send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_ADD_CONFIG, add_config_);
    return true;
}

void MgmtThread::set_log_level(const messages::mgmt_ext::SetLogLevel &request)
{
    // first check if Mgmt also has to change log level
    std::string module_name = request.module_name();
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);

    if (module_name == m_module_name || module_name == "all") {
        LOG(DEBUG) << "received SET_LOG_LEVEL request: " << request;
        m_pLogger->set_log_level_state(eLogLevel(request.log_level()), request.new_state());
    }

    // then send it to all other modules, on the bus.
    messages::mgmt_ext::SetLogLevel set_log_level;
    set_log_level.set_new_state(request.new_state());
    set_log_level.set_log_level(request.log_level());

    set_log_level.set_module_name(module_name);
    for (auto &wg_p : m_workgroups) {
        auto &wg = wg_p.second;
        if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_SET_LOG_LEVEL, request)) {
            LOG(ERROR) << "Failed to send set log level request: " << request;
        }
    }
}

bool MgmtThread::handle_pull(std::string module_name, int64_t wgid, pull_call_data *call_data)
{
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(WARNING) << "got pull request from unrecognized workgroup: " << wgid;
        return false;
    }
    std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);

    messages::mgmt::SendChunk sendFile;

    if (common::string_utils::caseless_eq(module_name, m_module_name)) {
        LOG(ERROR) << "mgmt can't handle pull";
        return false;
    }

    auto &pipe_members = wg_it->second.pipe_members;
    auto pipe_it = pipe_members.find(module_name);
    if (pipe_it == pipe_members.end()) {
        LOG(WARNING) << "got push request to unrecognized module: " << module_name << " in wg: " << wgid;
        return false;
    }
    sendFile.set_source_module(module_name);
    sendFile.set_target_module("mgmt");
    sendFile.set_file_pos(0);
    sendFile.set_is_last_chunk(false);
    sendFile.set_id(m_next_file_reqid++);
    send_msg(wg_it->second.broker_socket, messages::enums::Opcode::MGMT_PULL_REQUEST, sendFile);
    m_pull_responders[sendFile.id()] = call_data;

    return true;
}

bool MgmtThread::verify_push(const std::string &filename, const std::string &module_name, int64_t wgid)
{
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(WARNING) << "got push request to unrecognized workgroup: " << wgid;
        return false;
    }
    auto &pipe_members = wg_it->second.pipe_members;
    auto pipe_it = pipe_members.find(module_name);
    if (pipe_it == pipe_members.end()) {
        LOG(WARNING) << "got push request to unrecognized module: " << module_name << " in wg: " << wgid;
        return false;
    }

    return true;
}
bool MgmtThread::send_chunk(const std::string &chunk, uint64_t file_pos, const std::string &filename,
                            const std::string &module_name, int64_t wgid, push_file_call_data *call_data)
{
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(WARNING) << "got push request to unrecognized workgroup: " << wgid;
        return false;
    }
    //std::transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);
    auto &pipe_members = wg_it->second.pipe_members;
    auto pipe_it = pipe_members.find(module_name);
    if (pipe_it == pipe_members.end()) {
        LOG(WARNING) << "got push request to unrecognized module: " << module_name << " in wg: " << wgid;
        return false;
    }
    messages::mgmt::SendChunk send_chunk;
    send_chunk.set_id(m_next_file_reqid++);
    m_push_responders[send_chunk.id()] = call_data;
    send_chunk.set_content(chunk);
    send_chunk.set_filename(filename);
    send_chunk.set_file_pos(file_pos);
    send_chunk.set_target_module(module_name);
    return send_msg(wg_it->second.broker_socket, messages::enums::Opcode::MGMT_PUSH_REQUEST, send_chunk);
}

void MgmtThread::handle_subscribe(std::string topic, listen_call_data *listener, int64_t wgid)
{
    if (wgid == -1) {
        for (auto &wg : m_workgroups) {
            handle_subscribe(topic, listener, wg.first);
        }
        return;
    }
    std::transform(topic.begin(), topic.end(), topic.begin(), ::tolower);
    if (topic == "all") {
        for (auto &stat_topic : m_stat_topics) {
            m_workgroups[wgid].publisher_.subscribe(listener, stat_topic.first);
        }
        return;
    }
    m_workgroups[wgid].publisher_.subscribe(listener, topic);
}

void MgmtThread::handle_unsubscribe(std::string topic, listen_call_data *listener, int64_t wgid)
{
    if (wgid == -1) {
        for (auto &wg : m_workgroups) {
            handle_unsubscribe(topic, listener, wg.first);
        }
        return;
    }
    std::transform(topic.begin(), topic.end(), topic.begin(), ::tolower);
    m_workgroups[wgid].publisher_.unsubscribe(listener, topic);
}

bool MgmtThread::reset_module(std::string module_name, int64_t wgid)
{
    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            reset_module(module_name, wg.first);
        }
        return true;
    }
    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "undefined wgid: " << wgid;
        return false;
    }
    auto &wg = wg_it->second;
    messages::mgmt::ResetMod resetMod;
    resetMod.set_module_name(module_name);
    LOG(INFO) << "Sending reset command to: " << module_name;
    if (!send_msg(wg.broker_socket, messages::enums::Opcode::MGMT_RESET, resetMod)) {
        LOG(ERROR) << "Failed sending message reset command to all modules";
        return false;
    }
    reset();
    return true;
}

void MgmtThread::list(const imif::messages::mgmt_ext::ListRequest &request, imif::messages::mgmt_ext::ListResponse &response,
                      int64_t wgid)
{
    const std::string &item_name = request.item_name();
    if (item_name == "workgroup") {
        for (auto &wg : m_workgroups) {
            auto list_item = response.add_list_item();
            list_item->set_wgid(wg.first);
            list_item->set_wgname(m_id2wgname[wg.first]);
        }
        return;
    } else if (item_name == "topic") {
        for (auto &top : m_stat_topics) {
            auto list_item = response.add_list_item();
            list_item->set_topic(top.first);
            list_item->set_wgid(top.second);
        }
        return;
    }

    if (wgid == -1) { // all workgroups
        for (auto &wg : m_workgroups) {
            list(request, response, wg.first);
        }
        return;
    }

    auto wg_it = m_workgroups.find(wgid);
    if (wg_it == m_workgroups.end()) {
        LOG(ERROR) << "no wg defined for wgid: " << wgid;
        return;
    }
    auto &wg = wg_it->second;

    if (item_name == "source") {
        if (request.id_or_all_case() == imif::messages::mgmt_ext::ListRequest::IdOrAllCase::kId) {
            auto source_id = request.id();
            auto source_it = wg.sources.find(source_id);
            if (source_it == wg.sources.end()) {
                LOG(WARNING) << "Requested to list non existing source id:" << source_id;
                return;
            }
            auto list_item = response.add_list_item();
            list_item->mutable_source()->CopyFrom(source_it->second);
            list_item->set_wgid(wgid);
        } else {
            for (auto &source : wg.sources) {
                auto list_item = response.add_list_item();
                list_item->mutable_source()->CopyFrom(source.second);
                list_item->set_wgid(wgid);
            }
        }
    } else if (item_name == "flow") {
        if (request.id_or_all_case() == imif::messages::mgmt_ext::ListRequest::IdOrAllCase::kId) {
            auto flow_id = request.id();
            auto flow_it = wg.flows.find(flow_id);
            if (flow_it == wg.flows.end()) {
                LOG(WARNING) << "Requested to list non existing flow id:" << flow_id;
                return;
            }
            auto list_item = response.add_list_item();
            list_item->mutable_flow()->CopyFrom(flow_it->second);
            list_item->set_wgid(wgid);
        } else {
            for (auto &flow : wg.flows) {
                auto list_item = response.add_list_item();
                list_item->mutable_flow()->CopyFrom(flow.second);
                list_item->set_wgid(wgid);
            }
        }
    } else if (item_name == "config") {
        std::string module = request.module();
        if (module.empty()) {
            for (auto configs_it = wg.configs.begin(); configs_it != wg.configs.end(); configs_it++) {
                list_config(request, response, configs_it->second, configs_it->first, wgid);
            }
        } else {
            auto configs_it = wg.configs.find(request.module());
            if (configs_it == wg.configs.end()) {
                LOG(WARNING) << "Module not found: " << request.module();
                return;
            }
            list_config(request, response, configs_it->second, configs_it->first, wgid);
        }
    } else {
        LOG(ERROR) << "unrecognized list request for: " << item_name;
    }
}

void MgmtThread::list_config(const imif::messages::mgmt_ext::ListRequest &request, imif::messages::mgmt_ext::ListResponse &response,
                             const std::map<uint32_t, messages::types::Config> &configs, std::string module_name, int64_t wgid)
{
    if (request.id_or_all_case() == imif::messages::mgmt_ext::ListRequest::IdOrAllCase::kAll) {
        for (auto &config : configs) {
            auto list_item = response.add_list_item();
            LOG(WARNING) << "Setting module: " << request.module();
            list_item->set_module(module_name);
            list_item->mutable_config()->CopyFrom(config.second);
            list_item->set_wgid(wgid);
        }
    } else {
        auto config_it = configs.find(request.id());
        if (config_it == configs.end()) {
            LOG(WARNING) << "Requested to list non existing config id:" << request.id();
            return;
        }
        auto list_item = response.add_list_item();
        list_item->set_module(module_name);
        list_item->mutable_config()->CopyFrom(config_it->second);
        list_item->set_wgid(wgid);
    }
}
