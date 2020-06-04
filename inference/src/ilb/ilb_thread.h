
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

#ifndef _ILB_THREAD_H
#define _ILB_THREAD_H

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_event_queue_fd.h"
#include "common_mem_manager.h"
#include "common_message.h"
#include "common_rate_limiter.h"

#include "common_logging.h"
#include <chrono>
#include <unordered_map>

#include "ilb_inference.h"
#include "ilb_inference_openvino.h"

#include <messages/proto/inference.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>
#include <messages/proto/types.pb.h>

namespace imif {
namespace ilb {

class Irpipe {
public:
    Irpipe(){};
    ~Irpipe(){};
    size_t m_batch_size = 0;
    size_t m_outputSize = 0;

    std::unique_ptr<IlbInferenceEngine> m_inferenceEngine;

    inferenceInputVec m_frames; //holds all of the frames that are associated with this pipe

    uint32_t id;

    imif::common::rate_limiter m_rate_limiter;
    std::shared_ptr<imif::common::shmem_pool> m_pool;
    std::shared_ptr<imif::common::shmem_buff> m_currentBuff = nullptr;

    // Ilb statistics //
    uint64_t m_total_frames = 0;
    uint64_t m_total_dropped_results = 0;
    uint64_t m_aggregated_total_frames = 0;
    uint64_t m_total_inferences = 0;
    uint64_t m_aggregated_inferences = 0;
    uint64_t m_skipped_frames = 0;
    uint64_t m_stat_reports = 0;

private:
};

class IlbThread : public common::broker_thread {
public:
    IlbThread(const std::string broker_uds, uint32_t moudle_id, int32_t device_num, const messages::mgmt::GlobalConfig &config,
              std::shared_ptr<common::event_queue_fd> queue);
    ~IlbThread();

    void push_event(messages::enums::Opcode opcode, const google::protobuf::Message &msg) { m_event_queue.push_event(opcode, msg); }

    void push_event(messages::enums::Opcode opcode) { m_event_queue.push_event(opcode); }

protected:
    virtual bool post_init() override;
    virtual bool before_select() override;
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override;

private:
    enum eSTSreadBSdata {
        STS_READ_NO_ERROR = 0x1,
        STS_READ_MORE_DATA = 0x2,
        STS_READ_RUN_INFERENCE = 0x4,
        STS_READ_ERROR = 0x8,
        STS_READ_FATAL = 0x10
    };

    enum eSTSrunInference { STS_INFERENCE_NO_ERROR = 0x1, STS_INFERENCE_ERROR = 0x2, STS_INFERENCE_FATAL = 0x10 };

    void reset();

    bool global_config(const messages::mgmt::GlobalConfig &global_config);

    bool add_config(const messages::types::Config &config);
    bool add_flow(const messages::types::Flow &flow);

    bool handle_frame(const messages::types::FrameReady &frame);

    bool remove_config(uint32_t config_id);
    bool remove_flow(uint32_t flow_id);

    void handle_enable();
    void handle_disable();

    void save_frame(const messages::types::FrameInfo &frame_info);

    eInferenceEngineStatus runInference(std::shared_ptr<Irpipe> pipe);
    messages::inference::RawResult getResults(std::shared_ptr<Irpipe> pipe);
    void logStats(std::shared_ptr<Irpipe> pipe);
    bool sendResult(inferenceResult &results);
    bool ignoreFlow(uint32_t flow_id);

private:
    const int SELECT_TIMEOUT_MSEC = 100;
    const int WORK_REPORT_INTRVAL_MSEC = 2000;
    const int STATISTICS_INTRVAL_MSEC = 1000;
    const uint AGGREGATED_STATISTICS = 10; //will report average stats every AGGREGATED_STATISTICS*STATISTICS_INTRVAL_MSEC
    const uint MINIMUM_INFER_TIME_MSEC = 4;

    // ILb management and module configuration //
    std::string m_module_name;

    std::chrono::steady_clock::time_point m_next_register;
    bool m_registered = false;
    bool m_enabled = false;
    int32_t m_device_num = -1;

    std::string m_dump_path;
    std::string m_collect_stats_path;
    size_t m_collect_stats_frames = 0;

    // ILb thread related members //
    std::chrono::steady_clock::time_point m_work_last_report_timestamp;
    std::map<uint32_t, std::map<uint32_t, messages::types::Stage>> m_flows; // key - flow_id -> key - stage_id
    std::map<uint32_t, std::map<uint32_t, std::shared_ptr<imif::common::shmem_pool>>>
        m_pool_input_map; // // key - flow_id -> key - stage_id

    // Ilb Inference and piping/engines members //
    std::unordered_map<uint32_t, std::shared_ptr<Irpipe>> m_pipes; //mapping config <-> pipe
    std::vector<uint32_t> m_ignored_flows;

    // Ilb logging
    std::chrono::steady_clock::time_point m_statistics_report_timestamp;

    common::event_queue_fd m_event_queue;
    std::shared_ptr<common::event_queue_fd> m_raw_results_queue = nullptr;
};

//helper debug class, can be removed later on
class IlbDebug {
public:
    std::ofstream m_ilbRgbOutfile;
    std::string m_ilbFileName;
    void ilbCreateFile(std::string fileName);
    void ilbWriteToFile(uint8_t *data, size_t size);

private:
    std::string get_name() { return "IlbDebug"; }
};
} // namespace ilb
} // namespace imif

#endif
