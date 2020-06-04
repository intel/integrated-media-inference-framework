
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

#include "inference_thread.h"
#include "common_os_utils.h"
#include "common_string_utils.h"

#include <messages/proto/enums.pb.h>
#include <messages/proto/mgmt.pb.h>

using namespace imif;
using namespace common;
using namespace inference;

InferenceThread::InferenceThread(const std::string broker_uds, imif::common::logging *pLogger)
    : broker_thread("INFERENCE_THREAD", broker_uds), m_broker_path(broker_uds), m_module_name("inference"), m_pLogger(pLogger)
{
    m_next_register = m_statistics_report_timestamp = std::chrono::steady_clock::now();
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_global_config.Clear();
    m_inference_threads.clear();
    m_global_config.Clear();
    m_config_to_device.clear();
}

InferenceThread::~InferenceThread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void InferenceThread::reset()
{
    LOG(INFO) << "reset()";
    for (auto inference_thread : m_inference_threads) {
        inference_thread.second.ilb_thread->push_event(messages::enums::Opcode::MGMT_RESET);
        inference_thread.second.irp_thread->push_event(messages::enums::Opcode::MGMT_RESET);
    }

    m_enabled = false;
}

void InferenceThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";

    for (auto inference_thread : m_inference_threads) {
        inference_thread.second.ilb_thread->stop();
        inference_thread.second.irp_thread->stop();
    }

    should_stop = true;
    reset();
}

bool InferenceThread::post_init()
{
    LOG(INFO) << "InferenceThread::init()";

    // Register to bus messages
    subscribe({messages::enums::Opcode::MGMT_ADD_FLOW, messages::enums::Opcode::MGMT_REMOVE_FLOW,
               messages::enums::Opcode::MGMT_ADD_CONFIG, messages::enums::Opcode::MGMT_REMOVE_CONFIG,
               messages::enums::Opcode::MGMT_GLOBAL_CONFIG, messages::enums::Opcode::MGMT_REGISTER_RESPONSE,
               messages::enums::Opcode::MGMT_ENABLE, messages::enums::Opcode::MGMT_SET_LOG_LEVEL,
               messages::enums::Opcode::MGMT_RESET, messages::enums::Opcode::MGMT_PUSH_REQUEST});

    return true;
}

bool InferenceThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
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

        m_module_id = response.module_id();

        LOG(DEBUG) << "Recieved MGMT_REGISTER_RESPONSE";
        m_registered = true;

    } break;
    case messages::enums::Opcode::MGMT_ENABLE: {
        messages::mgmt::Enable request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Enable request";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        m_enabled = request.enable();
        LOG(DEBUG) << "Recieved MGMT_ENABLE=" << m_enabled;
        handle_enable(request);
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

        LOG(DEBUG) << "received SET_LOG_LEVEL request: " << request;
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

        if (!remove_flow(request)) {
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

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            return true;
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
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_PUSH_REQUEST: {
        messages::mgmt::SendChunk send_chunk;
        if (!send_chunk.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing sendFile";
            return false;
        }
        if (!common::string_utils::caseless_eq(send_chunk.target_module(), m_module_name)) {
            return false;
        }
        messages::mgmt::AckChunk ack;
        ack.set_id(send_chunk.id());
        ack.set_is_last_chunk(send_chunk.is_last_chunk());
        bool success = receive_chunk(send_chunk);
        ack.set_success(success);
        send_msg(sd, messages::enums::Opcode::MGMT_PUSH_RESPONSE, ack);
    } break;
    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
    } break;
    }

    return true;
}

bool InferenceThread::receive_chunk(messages::mgmt::SendChunk &send_chunk)
{
    std::string target_dir = "downloads";
    std::string filename = string_utils::str_split(send_chunk.filename(), '/').back();
    os_utils::make_dir(target_dir);
    std::ofstream output_stream;
    if (send_chunk.file_pos()) {
        output_stream.open(target_dir + "/" + filename, std::ios::binary | std::ios::app);
    } else {
        output_stream.open(target_dir + "/" + filename, std::ios::binary); // overwrite possible existing file with the new one.
    }
    if (!output_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << send_chunk.filename() << " for writing!!\n";
        return false;
    }
    if (!output_stream.write(send_chunk.content().c_str(), send_chunk.content().size())) {
        LOG(ERROR) << "ERROR: Could not write to file " << send_chunk.filename();
        return false;
    }
    output_stream.close();
    return true;
}

bool InferenceThread::before_select()
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

    logStats();

    return true;
}

//this routine prints various statistics to stdout
void InferenceThread::logStats() { return; }

bool InferenceThread::add_config(const messages::mgmt::AddConfig &request)
{
    auto config = request.config();
    messages::inference::Config ilbConfig;
    if (!config.config().UnpackTo(&ilbConfig)) {
        LOG(ERROR) << "Failed getting config";
        return false;
    }
    LOG(INFO) << "add_config id: " << config.id();

    uint32_t device_num = ilbConfig.hw_device_num();
    auto &inference_thread = m_inference_threads[device_num];
    if (!inference_thread.ilb_thread) {

        inference_thread.raw_results_queue = std::make_shared<common::event_queue_fd>();
        if (!inference_thread.raw_results_queue) {
            LOG(FATAL) << "Failed allocating queue for device " << device_num;
            m_inference_threads.erase(device_num);
            return false;
        }

        LOG(DEBUG) << "Creating ilb thread for device " << device_num;
        inference_thread.ilb_thread = std::make_shared<ilb::IlbThread>(m_broker_path, m_module_id, device_num, m_global_config,
                                                                       inference_thread.raw_results_queue);
        if (!inference_thread.ilb_thread) {
            LOG(FATAL) << "Failed allocating ilb thread for device " << device_num;
            m_inference_threads.erase(device_num);
            return false;
        }
        inference_thread.ilb_thread->start();

        LOG(DEBUG) << "Creating irp thread for device " << device_num;
        inference_thread.irp_thread = std::make_shared<irp::IrpThread>(m_broker_path, m_module_id, device_num, m_global_config,
                                                                       inference_thread.raw_results_queue);
        if (!inference_thread.irp_thread) {
            LOG(FATAL) << "Failed allocating irp thread for device " << device_num;
            m_inference_threads.erase(device_num);
            return false;
        }
        inference_thread.irp_thread->start();
    }

    inference_thread.ilb_thread->push_event(messages::enums::Opcode::MGMT_ADD_CONFIG, request);
    inference_thread.irp_thread->push_event(messages::enums::Opcode::MGMT_ADD_CONFIG, request);

    m_config_to_device[config.id()] = device_num;

    return true;
}

bool InferenceThread::add_flow(const messages::mgmt::AddFlow &request)
{
    for (auto inference_thread : m_inference_threads) {
        if (!inference_thread.second.ilb_thread) {
            LOG(ERROR) << "inference thread is not allocated";
            return false;
        }
        inference_thread.second.ilb_thread->push_event(messages::enums::Opcode::MGMT_ADD_FLOW, request);
        inference_thread.second.irp_thread->push_event(messages::enums::Opcode::MGMT_ADD_FLOW, request);
    }
    return true;
}

bool InferenceThread::remove_config(messages::mgmt::RemoveConfig &request)
{
    uint32_t config_id = request.config_id();
    LOG(DEBUG) << "Removing config id #" << config_id;
    auto it = m_config_to_device.find(config_id);
    if (it == m_config_to_device.end()) {
        LOG(ERROR) << "Unknown config id " << config_id;
        return false;
    }

    uint32_t device_num = it->second;
    auto &inference_threads = m_inference_threads[device_num];
    inference_threads.ilb_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_CONFIG, request);
    inference_threads.rfc--;
    inference_threads.irp_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_CONFIG, request);
    inference_threads.rfc--;
    if (inference_threads.rfc == 0) {
        inference_threads.ilb_thread->stop();
        inference_threads.ilb_thread = nullptr;
        inference_threads.irp_thread->stop();
        inference_threads.irp_thread = nullptr;
        m_inference_threads.erase(device_num);
    }

    return true;
}

bool InferenceThread::remove_flow(messages::mgmt::RemoveFlow &request)
{
    for (auto inference_thread : m_inference_threads) {
        inference_thread.second.ilb_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_FLOW, request);
        inference_thread.second.irp_thread->push_event(messages::enums::Opcode::MGMT_REMOVE_FLOW, request);
    }
    return true;
}

void InferenceThread::handle_enable(messages::mgmt::Enable &request)
{
    for (auto inference_thread : m_inference_threads) {
        inference_thread.second.ilb_thread->push_event(messages::enums::Opcode::MGMT_ENABLE, request);
        inference_thread.second.irp_thread->push_event(messages::enums::Opcode::MGMT_ENABLE, request);
    }
}

bool InferenceThread::global_config(const messages::mgmt::GlobalConfig &global_config)
{
    m_global_config.CopyFrom(global_config);
    if (!global_config.log_level().empty()) {
        LOG(INFO) << "received SET_LOG_LEVEL request: " << global_config.log_level();
        m_pLogger->set_log_level(global_config.log_level());
    }

    for (auto inference_thread : m_inference_threads) {
        inference_thread.second.ilb_thread->push_event(messages::enums::Opcode::MGMT_GLOBAL_CONFIG, global_config);
        inference_thread.second.irp_thread->push_event(messages::enums::Opcode::MGMT_GLOBAL_CONFIG, global_config);
    }

    return true;
}
