
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

#include "ilb_thread.h"
#include "common_os_utils.h"
#include "common_string_utils.h"

#include <functional>
#include <math.h>

#include <messages/proto/enums.pb.h>
#include <messages/proto/mgmt.pb.h>

#include <iostream>

using namespace imif;
using namespace common;
using namespace ilb;

// Override easylogging LOG definition adding the thread name
#ifdef LOG
#undef LOG
#endif
#define LOG(LEVEL) CLOG(LEVEL, ELPP_CURR_FILE_LOGGER_ID) << "[" + get_name() + "]: "

IlbDebug g_ilbDebug;

IlbThread::IlbThread(const std::string broker_uds, uint32_t module_id, int32_t device_num,
                     const messages::mgmt::GlobalConfig &config, std::shared_ptr<common::event_queue_fd> queue)
    : broker_thread("ILB_THREAD" + std::to_string(device_num), broker_uds), m_module_name("inference"), m_device_num(device_num),
      m_raw_results_queue(queue)
{
    m_work_last_report_timestamp = std::chrono::steady_clock::now();
    m_next_register = m_statistics_report_timestamp = std::chrono::steady_clock::now();
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_module_id = module_id;
    global_config(config);
    m_flows.clear();
    m_pipes.clear();
    m_ignored_flows.clear();
    m_pool_input_map.clear();
    m_event_queue.clear();
}

IlbThread::~IlbThread()
{
    LOG(TRACE) << "destructor()";
    for (auto &pipe : m_pipes) {
        pipe.second->m_inferenceEngine->unloadNetwork();
    }

    reset();
}

void IlbThread::reset()
{
    LOG(TRACE) << "reset()";

    for (auto &pipe : m_pipes) {
        pipe.second->m_frames.clear();
        pipe.second->m_currentBuff = nullptr;
        pipe.second->m_pool = nullptr;
        pipe.second->m_inferenceEngine->unloadNetwork();
    }
    m_pipes.clear();

    m_pool_input_map.clear();
    common::shmem_buff_factory::shmem_pool_map.clear();

    m_enabled = false;
}

void IlbThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";

    should_stop = true;
    reset();
}

bool IlbThread::post_init()
{
    LOG(TRACE) << "init()";
    // subscribe({messages::enums::Opcode::MGMT_ENABLE});

    int events_fd = m_event_queue.get_events_fd();
    if (events_fd > 0) {

        auto sd = std::make_shared<Socket>(events_fd);
        add_socket(sd);
    } else {
        LOG(ERROR) << "Invalid file descriptor: " << events_fd;
        should_stop = true;
        return false;
    }

    return true;
}

bool IlbThread::handle_msg(std::shared_ptr<Socket> sd)
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
    }

    return true;
}

bool IlbThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
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

        if (!request.sub_module().empty()) {
            if (request.sub_module() != "ilb") {
                break;
            }
        }

        m_enabled = request.enable();
        LOG(DEBUG) << "Recieved MGMT_ENABLE=" << m_enabled;
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
    case messages::enums::Opcode::DECODED_FRAME_READY: {
        messages::types::EventFrameReady requests;
        if (!requests.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing EventFrameReady message from MDECODE";
            return false;
        }
        for (auto request : requests.efr()) {
            if (!handle_frame(request)) {
                LOG(ERROR) << "Couldn't handle frame: " << request;
                return false;
            }
        }

    } break;
    // gracefully ignore msgs
    case messages::enums::MGMT_REGISTER_REQUEST:
    case messages::enums::MGMT_ADD_SOURCE:
    case messages::enums::MGMT_START_FLOW:
        break;
    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
    } break;
    }

    return true;
}

bool IlbThread::handle_frame(const messages::types::FrameReady &frame)
{
    const uint32_t flow_id = frame.frame_info().flow().id();

    bool skip_frame;

    if (m_flows.find(flow_id) == m_flows.end()) {
        return true;
    }

    std::shared_ptr<common::shmem_pool> pool = nullptr;
    std::shared_ptr<common::shmem_buff> buff = nullptr;

    auto stages_map = m_flows[flow_id];
    for (auto stage_id : frame.frame_info().flow().stage_id()) {
        auto stage_it = stages_map.find(stage_id);
        if (stage_it == stages_map.end()) {
            continue;
        }
        if (!pool && !frame.frame_info().frame_empty()) {
            pool = common::shmem_buff_factory::get_shmem_pool(frame.buff().shmkey(), frame.buff().shmsize());
            if (!pool) {
                LOG(ERROR) << "Can't get shm_pool for key=" << int(frame.buff().shmkey());
                return false;
            }

            buff = std::make_shared<shmem_buff>(pool, frame.buff());
            if (!buff) {
                LOG(ERROR) << "Failed getting shmem buff";
                return false;
            }
        }

        uint32_t config_id = stage_it->second.config_id();
        auto pipe_it = m_pipes.find(config_id);
        if (pipe_it == m_pipes.end()) {
            LOG(ERROR) << "handle_frame: unknown config_id: " << config_id;
            return false;
        }

        auto pipe = pipe_it->second;

        m_pool_input_map[flow_id][stage_id] = pool;
        if (buff && !buff->is_valid()) {
            LOG(DEBUG) << "Flow " << flow_id << " Not synced with producer, drop...";
            return true;
        }

        if (!m_enabled) {
            LOG(TRACE) << "ilb disabled";
            return true;
        }

        pipe->m_total_frames++;

        auto frame_info = frame.frame_info();
        if (frame_info.frame_empty()) {
            LOG(DEBUG) << "Ignoring frame since it's empty";
        } else if (ignoreFlow(flow_id)) {
            LOG(DEBUG) << "Ignoring frame since flow " << flow_id << " was excluded";
            frame_info.set_skip_frame(true);
        } else {
            pipe->m_rate_limiter.update_frame_counter(1);
            skip_frame = pipe->m_rate_limiter.check_frame_skip(frame_info);
            frame_info.set_skip_frame(skip_frame);
            pipe->m_skipped_frames += skip_frame ? 1 : 0;
            const auto frame_num = frame_info.frame().frame_num();
            LOG(DEBUG) << "incoming frame! m_frames.size=" << pipe->m_frames.size() << ". frame #" << frame_num
                       << " client_context " << frame_info.frame().client_context() << " (flow_id=" << flow_id
                       << ", pipe_id=" << pipe->id << ") skip_frame=" << skip_frame;
        }

        pipe->m_frames.push_back({frame_info, buff});
    }

    return true;
}

messages::inference::RawResult IlbThread::getResults(std::shared_ptr<Irpipe> pipe)
{
    messages::inference::RawResult results;

    if (pipe->m_inferenceEngine->hasPendingRequests() &&
        (pipe->m_inferenceEngine->getOldestDurationMs() > MINIMUM_INFER_TIME_MSEC)) {
        if (!pipe->m_currentBuff) {
            pipe->m_currentBuff = pipe->m_pool->alloc_buff(pipe->m_outputSize);
            if (!pipe->m_currentBuff) {
                LOG(ERROR) << "Failed allocating buffer size=" << pipe->m_outputSize;
                return results;
            }
        }

        while (pipe->m_inferenceEngine->getResult(pipe->m_currentBuff, results) > 0) {

            pipe->m_total_inferences += pipe->m_batch_size;

            sendResult(results);
            results.clear_efr();

            pipe->m_currentBuff = pipe->m_pool->alloc_buff(pipe->m_outputSize);
            if (!pipe->m_currentBuff) {
                LOG(ERROR) << "Failed allocating buffer size=" << pipe->m_outputSize
                           << " --> dropping result! (will not be sent to IRP)";
                pipe->m_total_dropped_results++;
                break;
            }
        }
    }
    return results;
}

bool IlbThread::ignoreFlow(uint32_t flow_id)
{

    for (uint i = 0; i < m_ignored_flows.size(); i++) {
        if (flow_id == m_ignored_flows[i]) {
            return true;
        }
    }

    return false;
}

eInferenceEngineStatus IlbThread::runInference(std::shared_ptr<Irpipe> pipe)
{
    if (pipe->m_frames.size() < pipe->m_batch_size) {
        //not enough frames
        return INFERENCE_ENGINE_NOT_ENOUGH_FRAMES;
    }

    uint inferrable = 0;
    uint skipped = 0;

    inferenceInputVec::iterator it = pipe->m_frames.begin();

    messages::inference::RawResult result;

    do {
        auto frame_info = it->first;
        if (frame_info.skip_frame() || frame_info.frame_empty()) {
            skipped++;
        } else {
            inferrable++;
        }
        it++;
    } while (inferrable < pipe->m_batch_size && it != pipe->m_frames.end());

    if (inferrable < pipe->m_batch_size) {
        LOG(DEBUG) << "Not enough frames to start inference (" << inferrable << " inferrable frames; " << skipped
                   << " skipped frames)";
        if (skipped > pipe->m_batch_size) {
            auto skip_it = pipe->m_frames.begin();
            while (skip_it != pipe->m_frames.end()) {
                if (skip_it->first.skip_frame() || skip_it->first.frame_empty()) {
                    result.add_efr()->mutable_frame_info()->CopyFrom(skip_it->first);
                    skip_it = pipe->m_frames.erase(skip_it);
                } else {
                    skip_it++;
                }
            }

            LOG(DEBUG) << "sending all skipped. efr_size=" << result.efr_size() << " m_frames_size=" << pipe->m_frames.size();
            sendResult(result);
        }

        return INFERENCE_ENGINE_NOT_ENOUGH_FRAMES;
    }

    //we have enough frames, check if the engine can handle them
    eInferenceEngineStatus status = pipe->m_inferenceEngine->runInference(pipe->m_frames);

    if (status == INFERENCE_ENGINE_NO_ERROR) {

        pipe->m_frames.erase(pipe->m_frames.begin(), pipe->m_frames.begin() + inferrable + skipped);

    } else if (status == INFERENCE_ENGINE_BUSY) {
        std::string str = "Engine is busy.";

        if (pipe->m_rate_limiter.get_rate_limit() == 0) {
            //automatic rate limit, force skip
            pipe->m_rate_limiter.update_dropped_frames(inferrable + skipped);

            inferenceInputVec::iterator it;
            for (it = pipe->m_frames.begin(); it != pipe->m_frames.begin() + inferrable + skipped; it++) {
                it->first.set_skip_frame(true);
            }

            str += " Forcefully skipping " + std::to_string(inferrable + skipped) + " frames";
        }

        LOG(DEBUG) << str;
    } else {
        LOG(DEBUG) << "runInference returned status=" << status;
    }

    return status;
}

bool IlbThread::sendResult(inferenceResult &results)
{
    m_raw_results_queue->push_event(messages::enums::Opcode::INFERENCE_RAW_RESULT_READY, results);
    //LOG(INFO) << "Sent INFERENCE_RAW_RESULT_READY: " << result;

    return true;
}

bool IlbThread::before_select()
{
    if (m_enabled) {
        int select_timeout = 20;

        auto last_report_time_msec =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_work_last_report_timestamp)
                .count();

        auto last_statistics_time_msec =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_statistics_report_timestamp)
                .count();

        if (last_statistics_time_msec > STATISTICS_INTRVAL_MSEC) {
            for (auto &pipe_pair : m_pipes) {
                logStats(pipe_pair.second);
            }
        }

        if (last_report_time_msec > WORK_REPORT_INTRVAL_MSEC) {
            m_work_last_report_timestamp = std::chrono::steady_clock::now();
            LOG(INFO) << "==>Work report";
        }

        //check results per pipe
        for (auto &pipe_pair : m_pipes) {
            auto pipe = pipe_pair.second;
            const uint minimum_inf_time_ms = 4;

            //update skip ratio, if required
            pipe->m_rate_limiter.update_skip_ratio();

            getResults(pipe);

            //if we have pending frames to be submitted to inference engines, do it now
            while (runInference(pipe) == INFERENCE_ENGINE_NO_ERROR)
                ;

            //change dynamic select time
            uint32_t timeout = minimum_inf_time_ms * pipe->m_inferenceEngine->getNumPendingRequests();
            if (timeout == 0) {
                timeout = SELECT_TIMEOUT_MSEC;
            }
            select_timeout = std::min((int)timeout, select_timeout);
        }

        set_select_timeout(select_timeout);
    }

    return true;
}

//this routine prints various statistics to stdout
void IlbThread::logStats(std::shared_ptr<Irpipe> pipe)
{
    std::stringstream statistic_stream;
    m_statistics_report_timestamp = std::chrono::steady_clock::now();

    statistic_stream << "ILB-Config #" << pipe->id << " :FPS (in):" << pipe->m_total_frames
                     << "\tFPS (out):" << pipe->m_total_inferences << "\tdropped results: " << pipe->m_total_dropped_results
                     << "\tskipped frames: " << pipe->m_skipped_frames;

    LOG(INFO) << statistic_stream.str();

    messages::mgmt::Statistics statistic;
    statistic.set_topic("ilb");
    statistic.set_stat(statistic_stream.str());
    send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);

    pipe->m_aggregated_total_frames += pipe->m_total_frames;
    pipe->m_aggregated_inferences += pipe->m_total_inferences;
    pipe->m_total_frames = pipe->m_total_inferences = pipe->m_total_dropped_results = pipe->m_skipped_frames = 0;
    pipe->m_stat_reports++;

    if (pipe->m_stat_reports == AGGREGATED_STATISTICS) {
        float average_frames_aggregated = pipe->m_aggregated_total_frames / pipe->m_stat_reports;
        float average_infer_aggregated = pipe->m_aggregated_inferences / pipe->m_stat_reports;

        statistic_stream.clear();
        statistic_stream << "\nILB-Config #" << pipe->id << ": average FPS (in):" << average_frames_aggregated
                         << "; average FPS (out):" << average_infer_aggregated << "\n";
        pipe->m_stat_reports = pipe->m_aggregated_total_frames = pipe->m_aggregated_inferences = 0;

        LOG(INFO) << statistic_stream.str();

        statistic.set_stat(statistic_stream.str());
        send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);
    }
}

bool IlbThread::add_config(const messages::types::Config &config)
{
    messages::inference::Config ilbConfig;
    if (!config.config().UnpackTo(&ilbConfig)) {
        LOG(ERROR) << "Failed getting config";
        return false;
    }
    LOG(INFO) << "add_config id: " << config.id();
    if (m_device_num != ilbConfig.hw_device_num()) {
        LOG(ERROR) << "Got add config request for wrong device";
        return false; //not meant for this device
    }

    subscribe({messages::enums::Opcode::DECODED_FRAME_READY});

    LOG(INFO) << "ILB: add_config id#: " << config.id() << "\n"
              << "-------------------\n"
              << "     batch_size  = " << ilbConfig.batch_size() << "\n"
              << "     engine_type = " << ilbConfig.engine_type() << "\n"
              << "     model_path  = " << ilbConfig.model_path() << "\n"
              << "     device #    = " << ilbConfig.hw_device_num() << "\n";

    auto ilb_pipe = std::make_shared<Irpipe>();
    ilb_pipe->id = config.id();
    ilb_pipe->m_batch_size = ilbConfig.batch_size();

    if (ilbConfig.engine_type() == "openvino") {
        ilb_pipe->m_inferenceEngine = std::unique_ptr<OpenVinoInferenceEngine>(new OpenVinoInferenceEngine());
        if (!ilb_pipe->m_inferenceEngine) {
            LOG(FATAL) << "Failed allocating inference engine!";
            return false;
        }

        INF_ENGINE_CHECK_STATUS(ilb_pipe->m_inferenceEngine->setDevice(ilbConfig.engine_device()));
    } else {
        LOG(ERROR) << "Unknown engine type! " << ilbConfig.engine_type();
        return false;
    }

    INF_ENGINE_CHECK_STATUS(ilb_pipe->m_inferenceEngine->setDevice(ilbConfig.hw_device_num()));

    messages::inference::OptionalConfig optional_config;
    if (!ilbConfig.optional_config().UnpackTo(&optional_config)) {
        LOG(INFO) << "Optional config is not set - using empty config";
    }

    //load network
    INF_ENGINE_CHECK_STATUS(ilb_pipe->m_inferenceEngine->loadNetwork(
        ilbConfig.model_path(), optional_config.openvino_n_threads(), ilbConfig.batch_size(), ilbConfig.model_type(),
        ilbConfig.num_of_inference_requests(), m_collect_stats_frames, m_collect_stats_path, ilbConfig.inference_input_precision(),
        optional_config.hetero_dump_graph_dot()));

    ilb_pipe->m_outputSize = ilb_pipe->m_inferenceEngine->outputSize();
    if (!ilb_pipe->m_outputSize) {
        LOG(FATAL) << "ilb_pipe.m_outputSize == 0";
        return false;
    }

    size_t memory_size = ilb_pipe->m_outputSize * ilb_pipe->m_batch_size * 24; //24 = max ICE engines * 2
    int pid = common::os_utils::get_pid();
    int shmkey = (pid << 8) | ilb_pipe->id;
    auto pool = std::make_shared<imif::common::shmem_pool>(shmkey, memory_size);
    if (!pool) {
        LOG(FATAL) << "IlbThread: Failed allocating pool!";
        should_stop = true;
        return false;
    }
    if (!pool->attach()) {
        LOG(FATAL) << "IlbThread: Failed attaching to shmem";
        should_stop = true;
        return false;
    }

    ilb_pipe->m_pool = pool;

    ilb_pipe->m_rate_limiter.set_rate_limit(ilbConfig.inference_rate());
    LOG(INFO) << "[AddConfig]: config #" << ilb_pipe->id << " Inference per second limit:" << ilbConfig.inference_rate();

    m_pipes[ilb_pipe->id] = ilb_pipe;

    //debug
    g_ilbDebug.m_ilbFileName.clear();
    if (!m_dump_path.empty()) {
        static int num_of_pipes = 0;
        g_ilbDebug.ilbCreateFile(m_dump_path + std::to_string(num_of_pipes++));
    }

    return true;
}

bool IlbThread::add_flow(const messages::types::Flow &flow)
{
    uint32_t flow_id = flow.id();
    for (const auto &stage : flow.pipeline().stage()) {
        if (!common::string_utils::caseless_eq(stage.module_name(), m_module_name)) {
            continue;
        }
        auto pipe = m_pipes.find(stage.config_id());
        if (pipe == m_pipes.end()) {
            continue;
        }

        LOG(INFO) << "MGMT_ADD_FLOW id: " << flow_id << " stage: " << stage;
        m_flows[flow_id][stage.id()].CopyFrom(stage);
    }
    return true;
}

bool IlbThread::remove_config(uint32_t config_id)
{
    auto it = m_pipes.find(config_id);

    if (it == m_pipes.end()) {
        LOG(WARNING) << "no such config #" << config_id;
        return false;
    }

    for (auto flow_it : m_flows) {
        auto stage = std::find_if(flow_it.second.begin(), flow_it.second.end(),
                                  [config_id](const std::pair<uint32_t, messages::types::Stage> stage_pair) {
                                      return stage_pair.second.config_id() == config_id;
                                  });
        if (stage != flow_it.second.end()) {
            LOG(INFO) << "Cant remove pipe " << config_id << " as it is used by flow " << flow_it.first << " stage "
                      << stage->first;
            return false;
        }
    }

    LOG(DEBUG) << "Removing config id #" << config_id;

    auto pipe = it->second;
    pipe->m_inferenceEngine->unloadNetwork();
    pipe->m_pool.reset();
    m_pipes.erase(it);

    return true;
}

bool IlbThread::remove_flow(uint32_t flow_id)
{
    auto flow_it = m_flows.find(flow_id);
    if (flow_it == m_flows.end()) {
        LOG(WARNING) << "no such flow #" << flow_id;
        return false;
    }

    LOG(DEBUG) << "Removing flow id " << flow_it->first;

    for (auto stage_it : flow_it->second) {
        uint32_t config_id = stage_it.second.config_id();
        auto pipe = m_pipes[config_id];
        auto frame_it = pipe->m_frames.begin();
        while (frame_it != pipe->m_frames.end()) {
            if (flow_id == frame_it->first.flow().id()) {
                frame_it = pipe->m_frames.erase(frame_it);
            } else {
                ++frame_it;
            }
        }

        auto pool = m_pool_input_map[flow_id][stage_it.first];
        if (pool) {
            m_pool_input_map[flow_id].erase(stage_it.first);
            uint32_t shmkey = pool->shmkey();
            if (pool.use_count() == 2) {
                shmem_buff_factory::free_shmem_pool(shmkey);
                pool.reset();
            }
        }
    }

    m_flows.erase(flow_id);
    m_pool_input_map.erase(flow_id);

    return true;
}

void IlbThread::handle_enable() {}

void IlbThread::handle_disable()
{
    for (auto &pipe : m_pipes) {
        pipe.second->m_frames.clear();
    }
}

bool IlbThread::global_config(const messages::mgmt::GlobalConfig &global_config)
{
    if (!global_config.dump_path().empty()) {
        m_dump_path = global_config.dump_path();
        LOG(INFO) << "received dump_path: " << m_dump_path;
    }

    messages::inference::GlobalConfig ilb_global;
    if (global_config.optional_config().UnpackTo(&ilb_global)) {

        if (!ilb_global.collect_stats_path().empty()) {
            m_collect_stats_path = ilb_global.collect_stats_path();
            LOG(INFO) << "Collect_stats_path: " << m_collect_stats_path;
        }

        m_collect_stats_frames = (size_t)ilb_global.collect_stats_frames();
        if (m_collect_stats_frames > 0) {
            LOG(INFO) << "Collect_stats_frames: " << m_collect_stats_frames;
        }

        //set ignored streams
        for (auto flow_id : ilb_global.ignore_flows()) {
            m_ignored_flows.push_back(flow_id);
            LOG(DEBUG) << "including flow " << flow_id;
        }
    }

    return true;
}

void IlbDebug::ilbCreateFile(std::string fileName)
{
    m_ilbFileName = fileName;
    m_ilbRgbOutfile.open(m_ilbFileName, std::ofstream::binary);
    if (m_ilbRgbOutfile.fail()) {
        LOG(ERROR) << "Could not open output file " << m_ilbFileName;
    }
    m_ilbRgbOutfile.close();
}

void IlbDebug::ilbWriteToFile(uint8_t *data, size_t size)
{
    if (m_ilbFileName.empty()) {
        return;
    }

    m_ilbRgbOutfile.open(m_ilbFileName, std::ofstream::binary | std::ofstream::app);
    if (m_ilbRgbOutfile.fail()) {
        LOG(ERROR) << "Could not open output file " << m_ilbFileName;
        m_ilbRgbOutfile.close();
        return;
    }
    m_ilbRgbOutfile.write((char *)data, size);
    if (m_ilbRgbOutfile.fail()) {
        LOG(ERROR) << "Could not write to output file " << m_ilbFileName;
    }
    m_ilbRgbOutfile.close();
}
