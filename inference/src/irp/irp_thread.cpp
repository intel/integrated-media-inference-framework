
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
#include "irp_thread.h"

#include <dlfcn.h>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

#include <messages/header.h>
#include <messages/proto/enums.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>

using namespace imif;
using namespace common;
using namespace irp;
using namespace cv;

// Override easylogging LOG definition adding the thread name
#ifdef LOG
#undef LOG
#endif
#define LOG(LEVEL) CLOG(LEVEL, ELPP_CURR_FILE_LOGGER_ID) << "[" + get_name() + "]: "

IrpThread::IrpThread(const std::string broker_uds, uint32_t module_id, int32_t device_num,
                     const messages::mgmt::GlobalConfig &config, std::shared_ptr<common::event_queue_fd> queue)
    : broker_thread("IRP_THREAD" + std::to_string(device_num), broker_uds), m_broker_uds(broker_uds), m_module_name("inference"),
      m_device_num(device_num), m_raw_results_queue(queue)
{
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_last_stats = m_start_time = m_next_register = std::chrono::steady_clock::now();
    m_module_id = module_id;
    m_output_dump_stream.close();
    m_blob_results_stream_map.clear();
    m_yaml_results_stream_map.clear();
    m_flows.clear();
    m_pipes.clear();
    m_shmkey_rfc.clear();
    m_flow2shmkey.clear();
    m_ilb_outputs.clear();
    m_inf_cfg2shmkey.clear();
    m_latest_valid_output_map.clear();
    global_config(config);
}

IrpThread::~IrpThread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void IrpThread::reset()
{
    LOG(TRACE) << "reset()";
    m_resize_rgb_image_buff = nullptr;

    if (m_data_thread->is_running()) {
        LOG(INFO) << "m_data_thread->stop()";
        messages::inference::RawResult efr;
        m_data_thread->push_event(efr);
        m_data_thread->stop();
    }
    m_ilb_outputs.clear();

    for (auto it : m_yaml_results_stream_map) {
        if (it.second)
            it.second->close();
    }

    for (auto it : m_blob_results_stream_map) {
        if (it.second)
            it.second->close();
    }

    if (m_output_dump_stream.is_open())
        m_output_dump_stream.close();
    common::shmem_buff_factory::shmem_pool_map.clear();

    m_flow2shmkey.clear();
    m_shmkey_rfc.clear();

    m_inf_cfg2shmkey.clear();

    m_enabled = false;
}

void IrpThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    log_stats(true);
    should_stop = true;
    reset();
}

bool IrpThread::post_init()
{
    m_data_thread = std::make_shared<irp_data_thread>(this, m_broker_uds);

    int events_fd = m_event_queue.get_events_fd();
    if (events_fd > 0) {

        auto sd = std::make_shared<Socket>(events_fd);
        add_socket(sd);
    } else {
        LOG(ERROR) << "Invalid file descriptor: " << events_fd;
        should_stop = true;
        return false;
    }

    events_fd = m_raw_results_queue->get_events_fd();
    if (events_fd > 0) {

        auto sd = std::make_shared<Socket>(events_fd);
        add_socket(sd);
    } else {
        LOG(ERROR) << "Invalid file descriptor: " << events_fd;
        should_stop = true;
        return false;
    }

    subscribe({messages::enums::Opcode::INFERENCE_RAW_RESULT_READY});

    return true;
}

bool IrpThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
    case messages::enums::Opcode::MGMT_ENABLE: {
        messages::mgmt::Enable request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Enable";
            return false;
        }

        if (!request.sub_module().empty()) {
            if (request.sub_module() != "irp") {
                break;
            }
        }

        m_enabled = request.enable();
        LOG(DEBUG) << "Received MGMT_ENABLE=" << m_enabled;

        if (m_enabled) {
            handle_enable();
        } else {
            handle_disable();
        }
    } break;
    case messages::enums::Opcode::MGMT_RESET: {
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

    case messages::enums::INFERENCE_RAW_RESULT_READY: {
        if (!m_enabled) {
            break;
        }

        messages::inference::RawResult inference_result;
        if (!inference_result.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing EventFrameReady";
            return false;
        }

        m_incoming_inference_total += inference_result.efr_size();
        if (inference_result.efr_size() > 0) {
            LOG(DEBUG) << "INFERENCE_RAW_RESULT_READY: num of results=" << inference_result.efr_size()
                       << " framenum = " << inference_result.efr(0).frame_info().frame().frame_num() << ".."
                       << inference_result.efr(inference_result.efr_size() - 1).frame_info().frame().frame_num();
        }

        m_data_thread->push_event(inference_result);
    } break;

    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
        // return false;
    } break;
    }

    return true;
}

bool IrpThread::handle_msg(std::shared_ptr<Socket> sd)
{
    if (sd->getSocketFd() == m_event_queue.get_events_fd()) {
        auto event = m_event_queue.pop_event();
        if (!event) {
            LOG(ERROR) << "Got poll on event_queue socket but no event to pop...";
            return false;
        }

        if (!handle_msg(nullptr, messages::enums::Opcode(event->opcode), event->msg.get(), event->msg_len)) {
            LOG(ERROR) << "Failed handling event " << event->opcode;
            return false;
        }
    } else if (sd->getSocketFd() == m_raw_results_queue->get_events_fd()) {
        auto event = m_raw_results_queue->pop_event();
        if (!event) {
            LOG(ERROR) << "Got poll on event_queue socket but no event to pop...";
            return false;
        }

        if (!handle_msg(nullptr, messages::enums::Opcode(event->opcode), event->msg.get(), event->msg_len)) {
            LOG(ERROR) << "Failed handling event " << event->opcode;
            return false;
        }
    }

    return true;
}
bool IrpThread::before_select()
{
    if (!m_enabled) {
        return true;
    }

    //update skip ratio, if required.
    m_rate_limiter.update_skip_ratio();

    log_stats();

    return true;
}

void IrpThread::log_stats(bool force)
{

    auto time_since_last =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_stats).count();

    auto time_since_start =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_start_time).count();

    if (time_since_last < REPORT_INTRVAL_MSEC && !force) {
        return;
    }

    std::stringstream statistic_stream;

    statistic_stream << "\n-------------\n";
    statistic_stream << "Received inference results: " << m_incoming_inference_total << " FPS ("
                     << (double)m_incoming_inference_bytes * 8 / 1024 / 1024 * 1000 / time_since_last << " Mbps)\n";
    statistic_stream << "Inferences post processed: " << m_inferences_post_processed << " FPS\n";

    m_total_received_bytes += m_incoming_inference_bytes;
    statistic_stream << "Average total received data: " << std::setw(6)
                     << (double)m_total_received_bytes * 8 / 1024 / 1024 * 1000 / time_since_start << " Mbps\n";

    statistic_stream << "Total run is " << std::setw(6) << (double)time_since_start / 1000 << " seconds" << std::endl;

    LOG(INFO) << statistic_stream.str();

    messages::mgmt::Statistics statistic;
    statistic.set_topic(m_module_name);
    statistic.set_stat(statistic_stream.str());
    send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);

    m_incoming_inference_total = m_incoming_inference_bytes = 0;
    m_inferences_post_processed = 0;

    m_last_stats = std::chrono::steady_clock::now();
}

std::shared_ptr<uint8_t> IrpThread::alloc_shared_ptr_buffer(size_t size, std::string name)
{
    auto s_ptr = std::shared_ptr<uint8_t>(new uint8_t[size], [](uint8_t *obj) {
        if (obj)
            delete[] obj;
    });
    if (!s_ptr) {
        LOG(ERROR) << "Alloc s_ptr fail!!!, name: " << name;
    }
    return s_ptr;
}

void IrpThread::storeLatestOutput(messages::types::ResultReady output, uint32_t flow_id)
{
    m_latest_valid_output_map[flow_id] = output;
}

bool IrpThread::getLatestOutput(uint32_t flow_id, messages::types::ResultReady &output)
{
    auto it = m_latest_valid_output_map.find(flow_id);
    if (it == m_latest_valid_output_map.end()) {
        output.add_detected_object();
        LOG(DEBUG) << "Couldn't find last valid irp output";
        return false;
    }
    output = it->second;
    return true;
}

bool IrpThread::add_config(const messages::types::Config &typesConfig)
{

    messages::inference::Config config;
    if (!typesConfig.config().UnpackTo(&config)) {
        LOG(ERROR) << "Failed getting config";
        return false;
    }
    if (m_device_num != config.hw_device_num()) {
        LOG(ERROR) << "Got add config request for wrong device";
        return false; //not meant for this device
    }

    messages::inference::OptionalConfig optional_config;
    if (!config.optional_config().UnpackTo(&optional_config)) {
        LOG(INFO) << "Optional config is not set - using empty config";
    }

    auto result_processing_plugin = optional_config.result_processing_plugin();

    LOG(DEBUG) << "IRP: add_config id#: " << typesConfig.id() << "\n"
               << "-------------------\n"
               << "     output rate  = " << config.inference_rate() << "\n"
               << "     engine_type = " << config.engine_type() << "\n"
               << "     plugin_path  = " << result_processing_plugin << "\n";

    auto irp_pipe = std::make_shared<IrpPipe>();
    irp_pipe->id = typesConfig.id();

    if (config.engine_type() != "openvino") {
        LOG(FATAL) << "Unsupported network: " << config.engine_type();
        return false;
    }

    m_rate_limiter.set_rate_limit(-1);
    LOG(INFO) << "IRP output rate control:" << config.inference_rate();

    void *plugin_handle = dlopen(optional_config.result_processing_plugin().c_str(), RTLD_LAZY);
    if (plugin_handle == nullptr) {
        LOG(ERROR) << "Error loading plugin from " << optional_config.result_processing_plugin() << ": " << dlerror();
        return false;
    } else {
        void *plugin_get = dlsym(plugin_handle, "get_plugin");
        if (plugin_get == nullptr) {
            LOG(ERROR) << "Error finding symbol plugin_get: " << dlerror();
            dlclose(plugin_handle);
            return false;
        } else {
            IrpPlugin &interface = reinterpret_cast<IrpPlugin &(*)()>(plugin_get)();
            irp_pipe->m_plugin = std::make_shared<IrpPlugin *>(&interface);
        }
    }

    LOG(DEBUG) << "initializing plugin...";
    sIrpPluginConfig plugin_config;
    plugin_config.batch_size = config.batch_size();
    plugin_config.accuracy_threshold = optional_config.detection_threshold();
    plugin_config.default_boxes_file = optional_config.ssd_boxes_file();
    plugin_config.labels_file = optional_config.labels_file();
    plugin_config.max_number_of_objects = optional_config.max_num_of_bounding_boxes();
    (*irp_pipe->m_plugin.get())->initPlugin(plugin_config);
    irp_pipe->always_send_results = optional_config.always_send_results();

    m_pipes[irp_pipe->id] = irp_pipe;

    if (!m_data_thread->is_running()) {
        LOG(INFO) << "m_data_thread->start()";
        m_data_thread->start("irp_data_thread" + std::to_string(m_device_num));
    }

    return true;
}

bool IrpThread::remove_config(uint32_t config_id)
{
    m_pipes.erase(config_id);
    auto it = m_inf_cfg2shmkey.find(config_id);
    if (it != m_inf_cfg2shmkey.end()) {
        common::shmem_buff_factory::free_shmem_pool(it->second);
        m_inf_cfg2shmkey.erase(it);
    }
    return true;
}

bool IrpThread::add_flow(const messages::types::Flow &flow)
{
    LOG(INFO) << "ADDING FLOW: " << flow;
    uint32_t flow_id = flow.id();
    for (auto stage : flow.pipeline().stage()) {
        if (!common::string_utils::caseless_eq(stage.module_name(), m_module_name)) {
            continue;
        }

        if (m_pipes.find(stage.config_id()) == m_pipes.end()) {
            continue;
        }
        LOG(DEBUG) << "Found stage - flow " << flow_id << " stage " << stage.id() << " config " << stage.config_id();
        m_flows[flow_id][stage.id()] = stage;

        if (!m_global_config.collect_blob_results_path().empty()) {
            std::string filename = m_global_config.collect_blob_results_path() + "results_flow_" + std::to_string(flow_id) +
                                   "_stage_" + std::to_string(stage.id()) + ".bin";

            auto fs = std::make_shared<std::ofstream>(filename, std::ios::out);
            if (!fs) {
                LOG(ERROR) << "Failed allocating file stream!";
                return false;
            }

            if (fs->is_open()) {
                uint32_t key = (flow_id << 8) | stage.id();
                m_blob_results_stream_map[key] = fs;
                LOG(INFO) << "Flow:" << flow_id << " stage: " << stage.id() << "blob results will be saved to file: " << filename;
            } else {
                LOG(ERROR) << "Could not open " << filename << " for writing!";
            }
        }

        if (!m_global_config.collect_yaml_results_path().empty()) {
            std::string filename = m_global_config.collect_yaml_results_path() + "results_flow_" + std::to_string(flow_id) +
                                   "_stage_" + std::to_string(stage.id()) + ".yaml";

            auto fs = std::make_shared<std::ofstream>(filename, std::ios::out);
            if (!fs) {
                LOG(ERROR) << "Failed allocating file stream!";
                return false;
            }

            if (fs->is_open()) {
                *fs << "frames:\n";

                uint32_t key = (flow_id << 8) | stage.id();
                m_yaml_results_stream_map[key] = fs;
                LOG(INFO) << "Flow:" << flow_id << " stage: " << stage.id() << "yaml results will be saved to file: " << filename;
            } else {
                LOG(ERROR) << "Could not open " << filename << " for writing!";
            }
        }
    }
    return true;
}

bool IrpThread::remove_flow(uint32_t flow_id)
{
    LOG(INFO) << "REMOVING FLOW: " << flow_id;

    m_flows.erase(flow_id);
    auto yaml_result_it = m_yaml_results_stream_map.find(flow_id);
    if (yaml_result_it != m_yaml_results_stream_map.end()) {
        if (yaml_result_it->second) {
            yaml_result_it->second->close();
        }
    }
    auto blob_result_it = m_blob_results_stream_map.find(flow_id);
    if (blob_result_it != m_blob_results_stream_map.end()) {
        if (blob_result_it->second) {
            blob_result_it->second->close();
        }
    }
    for (auto &shmkey_pair : m_flow2shmkey[flow_id]) {
        if (--(m_shmkey_rfc[shmkey_pair.second]) <= 0) {
            common::shmem_buff_factory::free_shmem_pool(shmkey_pair.second);
        }
    }
    m_flow2shmkey.erase(flow_id);

    return true;
}

void IrpThread::saveOutputYaml(const uint32_t flow_id, const uint8_t stage_id, const messages::types::ResultReady &result)
{
    uint32_t key = (flow_id << 8) | stage_id;
    auto it = m_yaml_results_stream_map.find(key);
    if (it == m_yaml_results_stream_map.end()) {
        return;
    }

    auto fs = it->second;
    if ((!fs) || (!fs->is_open())) {
        return;
    }

    std::string yaml_frame = "";
    for (auto &object : result.detected_object()) {
        if (object.probability() > 0) {
            yaml_frame += "    -\n";

            yaml_frame += "        flow: " + std::to_string(result.frame_info().flow().id()) + "\n";
            yaml_frame += "        frame: " + std::to_string(result.frame_info().frame().frame_num()) + "\n";

            yaml_frame += "        label: " + object.label() + "\n";
            yaml_frame += "        prob: " + std::to_string(object.probability()) + "\n";
            yaml_frame += "        box: [" + std::to_string(object.box().coordiatex()) + "," +
                          std::to_string(object.box().coordiatey()) + "," + std::to_string(object.box().width()) + "," +
                          std::to_string(object.box().height()) + "]" + "\n";
        }
    }
    *fs << yaml_frame;
}

void IrpThread::saveOutputBinary(const uint32_t flow_id, const uint8_t stage_id, const uint8_t *buf, const size_t size)
{
    uint32_t key = (flow_id << 8) | stage_id;
    auto it = m_blob_results_stream_map.find(key);
    if (it == m_blob_results_stream_map.end()) {
        return;
    }

    auto fs = it->second;
    if ((!fs) || (!fs->is_open())) {
        return;
    }

    fs->write((char *)buf, size);
}

#ifdef DEBUG_UNIT_TEST
//Debug routine that saves an output rgb file with bounding boxes on it
void IrpThread::save_bounding_boxes(std::vector<DetectionResult> detectionResults, uint64_t frame_num)
{
    const uint64_t MAX_FRAMES = 5000; //don't want to kill the hard drive with enourmous video files
    const size_t IMAGE_WIDTH = m_module_config.input_width();
    const size_t IMAGE_HEIGHT = m_module_config.input_height();
    const size_t IMAGE_SIZE = IMAGE_WIDTH * IMAGE_HEIGHT * 3;
    if (m_resize_rgb_image_buff == nullptr) {
        m_resize_rgb_image_buff = alloc_shared_ptr_buffer(IMAGE_SIZE, "m_resize_rgb_image_buff");
        if (!m_resize_rgb_image_buff) {
            return;
        }
    }
    uint8_t *rgb_image = m_resize_rgb_image_buff.get();

    if (frame_num <= MAX_FRAMES && detectionResults.size() > 0) {

        //read the original frame (without the boxes)
        LOG(DEBUG) << "reading frame #" << frame_num;
        std::fstream io_stream;
        io_stream.open("irp_output.rgb", std::ios::in | std::ios::out | std::ios::binary);
        if (io_stream.fail()) {
            LOG(ERROR) << "ERROR: Could not open file: irp_output.rgb";
        }
        io_stream.seekg(frame_num * IMAGE_SIZE);
        io_stream.read((char *)rgb_image, IMAGE_SIZE);

        //draw the boxes (including labels)
        Mat image_matrix = Mat(IMAGE_HEIGHT, IMAGE_WIDTH, CV_8UC3, rgb_image);
        for (auto &detected_object : detectionResults) {
            std::string label = detected_object.label < m_labels.size()
                                    ? m_labels[detected_object.label]
                                    : "LABEL_NOT_FOUND_" + std::to_string(detected_object.label);
            label += " " + std::to_string(detected_object.detection_score);
            cv::rectangle(image_matrix, detected_object.bounding_box, cv::Scalar(0, 255, 0));
            putText(image_matrix, label, cv::Point(detected_object.bounding_box.x, detected_object.bounding_box.y + 15),
                    FONT_HERSHEY_PLAIN, 1, cv::Scalar(0, 255, 0), 1.5, LINE_4);
        }

        //write the frame with the bounding boxes
        io_stream.seekp(frame_num * IMAGE_SIZE);
        io_stream.write((char *)rgb_image, IMAGE_SIZE);
        io_stream.close();
    }
}

void IrpThread::save_frame_to_file(uint8_t *image, uint64_t frame_num)
{
    const size_t IMAGE_SIZE = m_module_config.input_width() * m_module_config.input_height() * 3;

    LOG(DEBUG) << "saving frame #" << frame_num << " to file";
    if (frame_num == 0) {
        m_output_dump_stream.open("irp_output.rgb", std::ofstream::binary | std::ofstream::trunc);
        if (m_output_dump_stream.fail()) {
            LOG(ERROR) << "ERROR: Could not open file: irp_output.rgb";
        }
    }
    if (m_output_dump_stream.is_open()) {
        m_output_dump_stream.seekp(frame_num * IMAGE_SIZE);
        m_output_dump_stream.write((char *)image, IMAGE_SIZE);
    }
}

#endif

void IrpThread::handle_enable()
{
    m_last_stats = m_start_time = std::chrono::steady_clock::now();
    m_total_received_bytes = 0;
}

void IrpThread::handle_disable() {}

bool IrpThread::global_config(const messages::mgmt::GlobalConfig &global_config)
{
    if (!common::string_utils::caseless_eq(global_config.module_name(), m_module_name)) {
        // ignore configs that wasnt sent to me
        return true;
    }

    if (!global_config.dump_path().empty()) {
        m_dump_path = global_config.dump_path();
        LOG(INFO) << "received dump_path: " << m_dump_path;
    }

    if (global_config.optional_config().UnpackTo(&m_global_config)) {
        auto collect_yaml_results_path = m_global_config.collect_yaml_results_path();
        if (!collect_yaml_results_path.empty()) {
            if (collect_yaml_results_path.back() != '/') {
                collect_yaml_results_path += std::string("/");
            }
            if (!os_utils::make_dir(collect_yaml_results_path)) {
                LOG(ERROR) << "can't create collect_yaml_results_path: " << collect_yaml_results_path;
            }

            LOG(INFO) << "Output results will be saved to path:" << collect_yaml_results_path;
            m_global_config.set_collect_yaml_results_path(collect_yaml_results_path);
        }

        auto collect_blob_results_path = m_global_config.collect_blob_results_path();
        if (!collect_blob_results_path.empty()) {
            if (collect_blob_results_path.compare(collect_blob_results_path.size() - 1, 1, "/") != 0) {
                collect_blob_results_path += std::string("/");
            }
            if (!os_utils::make_dir(collect_blob_results_path)) {
                LOG(ERROR) << "can't create collect_blob_results_path: " << collect_blob_results_path;
            }

            LOG(INFO) << "Output blob results will be saved to path:" << collect_blob_results_path;
            m_global_config.set_collect_blob_results_path(collect_blob_results_path);
        }
    }

    return true;
}

bool irp_data_thread::postProcess(messages::inference::RawResult &result)
{
    float *pOutputData = nullptr;
    size_t outputData_size = 0;
    bool next_stages_exist = false;
    bool send_results = false;

    messages::types::EventResultReady results_event;
    std::shared_ptr<common::shmem_buff> buff = nullptr;

    uint32_t image_id = 0;
    for (auto &efr : *result.mutable_efr()) {
        messages::types::ResultReady output;
        auto frame_info = efr.frame_info();
        uint32_t flow_id = frame_info.flow().id();
        uint32_t frame_num = frame_info.frame().frame_num();
        if (m_irp_thread->m_flows.find(flow_id) == m_irp_thread->m_flows.end()) {
            continue;
        }

        for (auto stage_id : frame_info.flow().stage_id()) {
            auto stages_map = m_irp_thread->m_flows[flow_id];
            auto stage_it = stages_map.find(stage_id);
            if (stage_it == stages_map.end()) {
                continue;
            }
            auto cfg_id = stage_it->second.config_id();
            if (frame_info.frame_empty()) {
                output.Clear();
                output.mutable_frame_info()->CopyFrom(frame_info);
            } else if (frame_info.skip_frame()) {
                m_irp_thread->getLatestOutput(flow_id, output);
                output.mutable_frame_info()->CopyFrom(
                    frame_info); //restore the frame's meta data after it has been overwritten with previously saved results
                LOG(DEBUG) << "frame " << frame_num << " of flow " << flow_id
                           << "  was skipped by ILB, copying last known good result";
            } else {
                if (!buff) {
                    buff = common::shmem_buff_factory::get_buff(result.buff());
                    if (!buff) {
                        LOG(ERROR) << "Failed getting buff: " << result.buff() << "(flow " << flow_id << ":" << frame_num << ")";
                        return false;
                    }
                    if (!buff->is_valid()) {
                        LOG(DEBUG) << "Not synced with producer, drop...";
                        return true;
                    }
                    m_irp_thread->m_incoming_inference_bytes += buff->buff_size();
                    m_irp_thread->m_inf_cfg2shmkey[cfg_id] = buff->shmkey();

                    m_irp_thread->saveOutputBinary(flow_id, stage_id, buff->ptr(), buff->buff_size());

                    pOutputData = (float *)buff->ptr();
                    outputData_size = buff->buff_size();
                }

                output.mutable_frame_info()->CopyFrom(frame_info);

                auto before_pp_ts = std::chrono::steady_clock::now();

                std::vector<sInferenceResult> results;
                uint32_t config_id = stage_it->second.config_id();
                auto pipe = m_irp_thread->m_pipes[config_id];
                if (pipe) {
                    (*pipe->m_plugin)->postProcess(frame_info, pOutputData, outputData_size, image_id, results);
                } else {
                    LOG(ERROR) << "could not find plugin for config_id " << config_id;
                    continue;
                }
                send_results = send_results || pipe->always_send_results;

                auto after_pp_ts = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(after_pp_ts - before_pp_ts).count();
                LOG(DEBUG) << "post-processing duration[us]:" << duration;

                uint32_t box_count = 0;
                for (auto &result : results) {
                    auto object = output.add_detected_object();
                    messages::types::BoundingBox box;
                    box.set_coordiatex(result.box.x);
                    box.set_coordiatey(result.box.y);
                    box.set_width(result.box.width);
                    box.set_height(result.box.height);
                    object->mutable_box()->CopyFrom(box);
                    object->set_label(result.label);
                    object->set_probability(result.probability);
                    box_count++;
                    LOG(DEBUG) << "### irp result, flow_id " << flow_id << ", config_id " << config_id << ", frame "
                               << frame_info.frame().frame_num() << ", client_context " << frame_info.frame().client_context()
                               << ": " << result.label << ", probability= " << result.probability;
                }

                if (box_count == 0) { //dummy object
                    output.mutable_frame_info()->CopyFrom(frame_info);
                    auto detected_object = output.add_detected_object();
                    messages::types::BoundingBox box;
                    box.set_width(0);
                    box.set_height(0);
                    detected_object->mutable_box()->CopyFrom(box);
                    detected_object->set_label("");
                    LOG(DEBUG) << "### irp result, flow_id " << flow_id << " frame " << frame_info.frame().frame_num()
                               << ": couldn't detect or classify any object";
                }

                m_irp_thread->storeLatestOutput(output, flow_id);
            }

            output.mutable_frame_info()->mutable_flow()->clear_stage_id();

            for (auto next_stage : stage_it->second.next_stage()) {
                output.mutable_frame_info()->mutable_flow()->add_stage_id(next_stage);
                next_stages_exist = true;
            }
            auto result = results_event.add_results();
            result->CopyFrom(output);

            //append results in yaml format, if enabled
            m_irp_thread->saveOutputYaml(flow_id, stage_id, *result);
        }

        image_id++;
    }
    if ((send_results || next_stages_exist) &&
        !common::broker_thread::send_msg(m_broker_socket, messages::enums::INFERENCE_RESULTS_READY, results_event)) {
        LOG(ERROR) << "Failed sending message INFERENCE_RESULTS_READY!";
    }
    m_irp_thread->m_inferences_post_processed += results_event.results_size();

    return true;
}

irp_data_thread::irp_data_thread(IrpThread *irp_thread, std::string broker_uds) : m_broker_uds(broker_uds), m_irp_thread(irp_thread)
{
}

bool irp_data_thread::init()
{
    m_broker_socket = std::make_shared<common::SocketClient>(m_broker_uds);
    if (!m_broker_socket) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds;
        return false;
    }
    const auto error_msg = m_broker_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds << " [ERROR: " << error_msg << "]";
        m_broker_socket.reset();
        return false;
    }
    return true;
}

bool irp_data_thread::work()
{
    auto ilb_result = m_queue.pop(true); //blocking

    LOG(DEBUG) << "irp_data_thread - starting to process inference results";
    postProcess(ilb_result);

    return true;
}

void irp_data_thread::push_event(messages::inference::RawResult &efr) { m_queue.push(efr); }
