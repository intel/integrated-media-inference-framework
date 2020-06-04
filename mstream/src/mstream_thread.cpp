
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

#include "mstream_thread.h"

#include "easylogging++.h"

#include "common_os_utils.h"
#include "common_string_utils.h"

#include <messages/proto/enums.pb.h>

#include <archive.h>
#include <archive_entry.h>

#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

using namespace imif;
using namespace common;
using namespace mstream;

#define SELECT_TIMEOUT_MSEC 100

bool archive_dir(const std::string &target_archive, const std::string &dir_name)
{
    struct archive *arc;
    struct archive_entry *entry;
    int len;

    if (!fs::is_directory(dir_name)) {
        LOG(ERROR) << dir_name << " is not a directory";
        return false;
    }

    arc = archive_write_new();
    if (arc == nullptr) {
        LOG(ERROR) << "Failed allocating archive!";
        archive_write_free(arc);
        return false;
    }

    if (ARCHIVE_OK != archive_write_add_filter_gzip(arc)) {
        LOG(ERROR) << "Failed creating archive!";
        archive_write_free(arc);
        return false;
    }
    if (ARCHIVE_OK != archive_write_set_format_pax_restricted(arc)) {
        LOG(ERROR) << "Failed creating archive!";
        archive_write_free(arc);
        return false;
    }

    if (ARCHIVE_OK != archive_write_open_filename(arc, target_archive.c_str())) {
        LOG(ERROR) << "Failed creating archive!";
        archive_write_close(arc);
        archive_write_free(arc);
        return false;
    }

    auto buff = std::shared_ptr<char>(new char[os_utils::MAX_CHUNK_SIZE], [](char *obj) {
        if (obj)
            delete[] obj;
    });
    if (!buff) {
        LOG(ERROR) << "Failed allocating buffer!";
        archive_write_close(arc);
        archive_write_free(arc);
        return false;
    }

    for (const auto &file : fs::directory_iterator(dir_name)) {
        std::string filepath = file.path();
        if (!fs::is_regular_file(filepath) && fs::is_symlink(filepath)) {
            continue;
        }
        entry = archive_entry_new();
        archive_entry_set_pathname(entry, filepath.c_str());
        archive_entry_set_size(entry, size_t(fs::file_size(filepath)));
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);
        archive_write_header(arc, entry);

        std::ifstream input_stream(filepath.c_str(), std::ifstream::in);
        input_stream.read(buff.get(), os_utils::MAX_CHUNK_SIZE);
        len = input_stream.gcount();
        while (len > 0) {
            archive_write_data(arc, buff.get(), len);
            input_stream.read(buff.get(), os_utils::MAX_CHUNK_SIZE);
            len = input_stream.gcount();
        }
        input_stream.close();
        archive_entry_free(entry);
    }

    archive_write_close(arc);
    archive_write_free(arc);

    return true;
}

MstThread::MstThread(const std::string broker_uds, imif::common::logging *pLogger)
    : broker_thread("MSTREAM_THREAD", broker_uds), m_module_name("mstream"), m_broker_uds(broker_uds), m_pLogger(pLogger),
      m_grpc_server_thread(broker_uds)
{
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_next_stats = std::chrono::steady_clock::now();
    m_start_time = std::chrono::steady_clock::now();
    m_next_register = std::chrono::steady_clock::now();

    m_rtsp_sources.clear();
    m_loadimage_threads.clear();
    m_configs.clear();
    m_rtsp_configs.clear();
}

MstThread::~MstThread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void MstThread::reset()
{
    LOG(TRACE) << "reset()";

    m_rtsp_sources.clear();
    m_configs.clear();

    m_grpc_server_thread.stop();
    m_grpc_server_thread.clear();
    for (auto loadimage_thread : m_loadimage_threads) {
        loadimage_thread.second->stop();
    }
    messages::mgmt::ResetMod request;
    m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_RESET, request);

    common::shmem_buff_factory::shmem_pool_map.clear();
    m_enabled = false;
}

void MstThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    log_stats(true);
    should_stop = true;

    m_rtsp_thread->stop();

    reset();
}

bool MstThread::post_init()
{
    // Register to bus messages
    subscribe({messages::enums::Opcode::MGMT_ADD_FLOW, messages::enums::Opcode::MGMT_REMOVE_FLOW,
               messages::enums::Opcode::MGMT_ADD_CONFIG, messages::enums::Opcode::MGMT_REMOVE_CONFIG,
               messages::enums::Opcode::MGMT_GLOBAL_CONFIG, messages::enums::Opcode::MGMT_REGISTER_RESPONSE,
               messages::enums::Opcode::MGMT_ENABLE, messages::enums::Opcode::MGMT_SET_LOG_LEVEL,
               messages::enums::Opcode::MGMT_RESET, messages::enums::Opcode::MGMT_ADD_SOURCE,
               messages::enums::Opcode::MGMT_REMOVE_SOURCE, messages::enums::Opcode::MGMT_START_FLOW,
               messages::enums::Opcode::MGMT_STOP_FLOW, messages::enums::Opcode::MGMT_PULL_REQUEST,
               messages::enums::Opcode::MGMT_PUSH_RESPONSE});

    m_rtsp_thread = std::make_shared<mstream_rtsp_thread>(m_broker_uds);
    if (!m_rtsp_thread) {
        LOG(ERROR) << "Failed allocating rtsp thread";
        return false;
    }
    m_rtsp_thread->start("rtsp_thread");

    return true;
}

bool MstThread::handle_enable()
{
    for (auto &elem : m_loadimage_threads) {
        elem.second->enable();
    }

    m_grpc_server_thread.enable();

    m_start_time = std::chrono::steady_clock::now();
    m_next_stats = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    return true;
}

bool MstThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
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

        LOG(INFO) << "Recieved MGMT_ENABLE";

        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_ENABLE, request);

        if (!m_enabled && request.enable()) {
            handle_enable();
        }

        m_enabled = request.enable();
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
    case messages::enums::Opcode::MGMT_ADD_SOURCE: {
        messages::mgmt::AddSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing AddSource";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore sources that wasnt sent to me
            return true;
        }
        LOG(INFO) << "MGMT_ADD_SOURCE: " << request;

        if (!add_source(request)) {
            // Send erro to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_SOURCE: {
        messages::mgmt::RemoveSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveSource";
            return false;
        }
        LOG(INFO) << "MGMT_REMOVE_SOURCE: " << request;
        if (!remove_source(request)) {
            // Send erro to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_ADD_FLOW: {
        messages::mgmt::AddFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Flow";
            return false;
        }

        LOG(INFO) << "MGMT_ADD_FLOW: " << request;

        if (!add_flow(request)) {
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

        if (!remove_flow(request)) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_START_FLOW: {
        messages::mgmt::StartSource request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing StreamAdd";
            return false;
        }

        LOG(INFO) << "Recieved MGMT_START_FLOW: " << request;

        if (!start_source(request.source_id())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_STOP_FLOW: {
        // TODO
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

        LOG(INFO) << "MGMT_ADD_CONFIG: " << request;

        if (!add_config(request)) {
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

        if (!remove_config(request)) {
        }
    } break;
    case messages::enums::Opcode::MGMT_PULL_REQUEST: {
        messages::mgmt::SendChunk sendFile;
        if (!sendFile.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing sendFile";
            return false;
        }
        if (sendFile.source_module() != m_module_name) {
            return true;
        }
        imif::common::os_utils::make_dir("../temp");
        std::string archive_filename = "../temp/module_logs.tar.gz";
        archive_dir(archive_filename, "../logs");
        sendFile.set_filename(archive_filename);
        sendFile.set_file_pos(0);
        if (!os_utils::read_file_chunk(sendFile)) {
            sendFile.set_is_last_chunk(true);
            sendFile.clear_content();
        }
        send_msg(sd, messages::enums::Opcode::MGMT_PUSH_REQUEST, sendFile);
    } break;
    case messages::enums::Opcode::MGMT_PUSH_RESPONSE: {
        messages::mgmt::SendChunk sendFile;
        if (!sendFile.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing sendFile";
            return false;
        }
        if (sendFile.source_module() != m_module_name) {
            return true;
        }
        if (!os_utils::read_file_chunk(sendFile)) {
            sendFile.clear_content();
            sendFile.set_is_last_chunk(true);
        }
        send_msg(sd, messages::enums::Opcode::MGMT_PUSH_REQUEST, sendFile);
        return true;
    } break;
    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
    } break;
    }
    return true;
}

void MstThread::log_stats(bool force)
{
    auto now = std::chrono::steady_clock::now();
    if (now > m_next_stats || force) {
        std::stringstream statistic_stream;

        auto sent_bytes = m_sent_bytes + m_grpc_server_thread.sent_bytes() + m_rtsp_thread->sent_bytes();
        for (auto image_thread : m_loadimage_threads) {
            sent_bytes += image_thread.second->sent_bytes();
            image_thread.second->reset_stats();
        }
        auto dropped_bytes = m_dropped_bytes + m_grpc_server_thread.dropped_bytes() + m_rtsp_thread->dropped_bytes();

        statistic_stream << "Current bps " << float(sent_bytes * 8) / 1024 / 1024 << " [Mbps]" << std::endl;
        statistic_stream << "Current dropped = " << float(dropped_bytes * 8) / 1024 / 1024 << " [Mbps]" << std::endl;
        statistic_stream << "Current fps decoded = " << float(m_grpc_server_thread.sent_frames()) << " [fps]" << std::endl;
        statistic_stream << "Time spent decoding this second = " << m_grpc_server_thread.time_spent_decoding_usec() / 1000
                         << " [msec]" << std::endl;

        m_total_sent_bytes += sent_bytes;
        m_total_dropped_bytes += dropped_bytes;
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_start_time).count();
        auto seconds = milliseconds / 1000;

        statistic_stream << "Total bps = " << float(m_total_sent_bytes * 8) / seconds / 1024 / 1024 << " [Mbps]" << std::endl;
        statistic_stream << "Total dropped = " << m_total_dropped_bytes << " [Bytes]" << std::endl;
        statistic_stream << "Total run is " << seconds << " seconds" << std::endl;

        LOG(INFO) << statistic_stream.str();

        messages::mgmt::Statistics statistic;
        statistic.set_topic(m_module_name);
        statistic.set_stat(statistic_stream.str());
        send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);

        m_sent_bytes = 0;
        m_dropped_bytes = 0;
        m_grpc_server_thread.reset_stats();
        m_rtsp_thread->reset_stats();
        m_next_stats = now + std::chrono::seconds(1);
    }
}

bool MstThread::before_select()
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

    log_stats();

    return true;
}

bool MstThread::add_config(const messages::mgmt::AddConfig &request)
{
    const messages::types::Config &config = request.config();
    messages::mstream::Config mstConfig;
    if (!config.config().UnpackTo(&mstConfig)) {
        LOG(ERROR) << "Failed getting mstream config";
        return false;
    }

    if (mstConfig.type() == messages::enums::StreamType::IMIF_SL) {
        if (!m_grpc_server_thread.is_running()) {
            if (!m_grpc_server_thread.start("grpc_thread")) {
                LOG(ERROR) << "failed to start grpc thread";
                return false;
            }
        }
        if (!m_grpc_server_thread.set_listening_port(mstConfig.listening_ip_port())) {
            LOG(ERROR) << "Failed to set GRPC port number";
            return false;
        }
    } else if (mstConfig.type() == messages::enums::StreamType::RTSP) {
        m_rtsp_configs.insert(config.id());
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_ADD_CONFIG, request);
    }

    m_configs[config.id()].CopyFrom(mstConfig);

    return true;
}

bool MstThread::remove_config(const messages::mgmt::RemoveConfig &request)
{
    auto config_id = request.config_id();
    if (m_rtsp_configs.count(config_id)) {
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_CONFIG, request);
        m_rtsp_configs.erase(config_id);
    }
    m_configs.erase(config_id);
    return true;
}

bool MstThread::add_flow(const messages::mgmt::AddFlow &request)
{
    const messages::types::Flow &flow = request.flow();
    uint32_t flow_id = flow.id();

    uint32_t source_id = flow.source_id();
    bool rtsp_flow = m_rtsp_sources.count(source_id);
    auto load_image_it = m_loadimage_threads.find(source_id);
    bool grpc_flow = m_grpc_server_thread.sources().find(source_id) != m_grpc_server_thread.sources().end();

    if ((load_image_it == m_loadimage_threads.end()) && !rtsp_flow && !grpc_flow) {
        LOG(ERROR) << "Can't add flow, source " << source_id << " does not exist";
        return false;
    }
    if (rtsp_flow) {
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_ADD_FLOW, request);
        return true;
    } else if (grpc_flow) {
        LOG(TRACE) << "Adding flow for GRPC";
    } else if (load_image_it != m_loadimage_threads.end() && load_image_it->second->get_started_source()) {
        LOG(ERROR) << "Can't add flow for playing stream! stream=" << source_id;
        return false;
    }

    // Make sure that NET isn't responsible for more then 1 stage
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

    uint32_t stage_id = stage.id();
    if (stage_id != 0) {
        LOG(ERROR) << "Undefined behaviour - MSS not suppose to be in the middle of the flow (stage_id != 0)";
        return false;
    }

    if (stage.config_case() != stage.kConfigId) {
        LOG(ERROR) << "config id isn't set!!!";
        return false;
    }

    uint32_t config_id = stage.config_id();
    auto config_it = m_configs.find(config_id);
    if (config_it == m_configs.end()) {
        LOG(ERROR) << "Can't add flow. config " << config_id << " not exist";
        return false;
    }

    messages::mstream::OptionalConfig optional_config;
    config_it->second.optional_config().UnpackTo(&optional_config);

    if (load_image_it != m_loadimage_threads.end()) {
        load_image_it->second->add_flow(flow, optional_config.batch_size());
    }

    if (grpc_flow) {
        if (!m_grpc_server_thread.add_flow(flow_id, stage)) {
            LOG(ERROR) << "Failed creating shared_buff for flow " << flow_id;
            should_stop = true;
            return false;
        }
    }

    return true;
}

bool MstThread::remove_flow(const messages::mgmt::RemoveFlow &request)
{
    auto flow_id = request.flow_id();
    LOG(TRACE) << "Removing flow " << flow_id;

    m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_FLOW, request);
    m_grpc_server_thread.flows().erase(flow_id);

    return true;
}

bool MstThread::add_source(const messages::mgmt::AddSource &request)
{
    const messages::types::Source &source = request.source();
    uint32_t source_id = source.id();
    if (m_rtsp_sources.count(source_id)) {
        LOG(ERROR) << "Already added rtsp client with source_id " << source_id;
        return true;
    }
    if (m_loadimage_threads.find(source_id) != m_loadimage_threads.end()) {
        LOG(ERROR) << "Already added file with source_id " << source_id;
        return true;
    }
    if (m_grpc_server_thread.sources().find(source_id) != m_grpc_server_thread.sources().end()) {
        LOG(ERROR) << "source id " << source_id << " already exists as grpc source";
        return false;
    }

    if (source.type() == messages::enums::StreamType::RTSP) {
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_ADD_SOURCE, request);
        m_rtsp_sources.insert(source_id);
    } else if (source.type() == messages::enums::StreamType::LOCAL_FILE) {
        auto imageload_thread = std::make_shared<ImageLoadThread>(source, m_broker_uds);
        if (!imageload_thread) {
            LOG(ERROR) << "Failed allocating thread for source id " << source_id;
            return false;
        }
        imageload_thread->start(std::string("ImageLoadThread_Source") + std::to_string(source_id));
        m_loadimage_threads[source_id] = imageload_thread;
    } else if (source.type() == messages::enums::StreamType::IMIF_SL) {
        if (!m_grpc_server_thread.sources().empty()) {
            LOG(ERROR) << "Only one GRPC source is supported, no more than one.";
            return false;
        }

        LOG(DEBUG) << "Recognized SL sources & added";
        m_grpc_server_thread.sources().emplace(source_id);
    } else {
        LOG(ERROR) << "Unknown sources type: " << int(source.type());
        return false;
    }

    return true;
}

bool MstThread::remove_source(const messages::mgmt::RemoveSource &request)
{
    auto source_id = request.source_id();
    auto rtsp_source_iter = m_rtsp_sources.find(source_id);
    auto loadimage_thread_it = m_loadimage_threads.find(source_id);

    if (rtsp_source_iter != m_rtsp_sources.end()) {
        LOG(DEBUG) << "Closing rtsp client with source_id " << source_id;
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_SOURCE, request);
    } else if (loadimage_thread_it != m_loadimage_threads.end()) {
        LOG(DEBUG) << "Closing load image thread for source_id " << source_id;
        loadimage_thread_it->second->stop();
        m_loadimage_threads.erase(loadimage_thread_it);
    } else {
        LOG(ERROR) << "Not suppose to happen...";
    }

    if (m_grpc_server_thread.sources().find(source_id) != m_grpc_server_thread.sources().end()) {
        LOG(DEBUG) << "Removing source_id " << source_id << " from GRPC sources";
        m_grpc_server_thread.sources().erase(source_id);
    }

    return true;
}

bool MstThread::start_source(uint32_t source_id)
{
    LOG(TRACE) << "Welcome to MstThread::start_source(uint32_t " << source_id << ")";
    auto rtsp_client = m_rtsp_sources.find(source_id);
    auto loadimage_thread_it = m_loadimage_threads.find(source_id);
    auto is_grpc_stream = m_grpc_server_thread.sources().find(source_id) != m_grpc_server_thread.sources().end();

    if ((loadimage_thread_it == m_loadimage_threads.end()) && (rtsp_client == m_rtsp_sources.end()) && !is_grpc_stream) {
        LOG(ERROR) << "Can't start source " << source_id << " not exist";
        return false;
    }

    if (rtsp_client != m_rtsp_sources.end()) {
        messages::mgmt::StartSource request;
        request.set_source_id(source_id);
        m_rtsp_thread->push_event(messages::enums::Opcode::MGMT_START_FLOW, request);
    } else if (is_grpc_stream) {
        LOG(INFO) << "GRPC Stream is always started";
    } else if (loadimage_thread_it != m_loadimage_threads.end()) {
        loadimage_thread_it->second->start_source();
    }
    return true;
}

bool MstThread::global_config(const messages::mgmt::GlobalConfig global_config)
{
    if (!common::string_utils::caseless_eq(global_config.module_name(), m_module_name)) {
        // ignore configs that wasnt sent to me
        return true;
    }

    if (!global_config.log_level().empty()) {
        m_pLogger->set_log_level(global_config.log_level());
        LOG(INFO) << "received SET_LOG_LEVEL request: " << global_config.log_level();
    }

    return true;
}
