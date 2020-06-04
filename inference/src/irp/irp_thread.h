
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

#ifndef _IRP_THREAD_H
#define _IRP_THREAD_H

#include "common_broker_thread.h"
#include "common_event_queue_fd.h"
#include "common_mem_manager.h"
#include "common_rate_limiter.h"
#include "common_thread_safe_queue.h"
#include "irp_plugin.h"

#include <messages/proto/inference.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/types.pb.h>

#include "common_logging.h"

#include <unordered_map>
#include <vector>

#include "opencv2/core/core_c.h"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/imgproc/types_c.h"
#include "opencv2/objdetect/objdetect.hpp"

namespace imif {
namespace irp {

class IrpPipe {
public:
    IrpPipe(){};
    ~IrpPipe(){};
    uint32_t id;
    bool always_send_results;

    std::shared_ptr<IrpPlugin *> m_plugin;

private:
};

class IrpThread;

class irp_data_thread : public common::thread_base {
public:
    irp_data_thread(IrpThread *m_irp_thread, std::string broker_uds);
    void push_event(messages::inference::RawResult &efr);

protected:
    virtual bool init() override;
    virtual bool work() override;

private:
    std::string m_broker_uds;
    std::shared_ptr<common::SocketClient> m_broker_socket = nullptr;
    const uint32_t SLEEP_USEC = 4000;
    IrpThread *m_irp_thread = nullptr;
    bool postProcess(messages::inference::RawResult &result);

    common::thread_safe_queue<messages::inference::RawResult> m_queue;
};

class IrpThread : public common::broker_thread {
public:
    IrpThread(const std::string broker_uds, uint32_t module_id, int32_t device_num, const messages::mgmt::GlobalConfig &config,
              std::shared_ptr<common::event_queue_fd> queue);
    ~IrpThread();

    virtual bool post_init() override;
    virtual bool before_select() override;

    void push_event(messages::enums::Opcode opcode, const google::protobuf::Message &msg) { m_event_queue.push_event(opcode, msg); }

    void push_event(messages::enums::Opcode opcode) { m_event_queue.push_event(opcode); }

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;
    bool handle_msg_internal(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len);
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override;

private:
    void reset();

    bool global_config(const messages::mgmt::GlobalConfig &global_config);

    bool add_config(const messages::types::Config &config);
    bool add_flow(const messages::types::Flow &flow);

    bool remove_config(uint32_t config_id);
    bool remove_flow(uint32_t flow_id);

    void handle_enable();
    void handle_disable();

    std::shared_ptr<uint8_t> alloc_shared_ptr_buffer(size_t size, std::string name);

    void storeLatestOutput(messages::types::ResultReady output, uint32_t flow_id);
    bool getLatestOutput(uint32_t flow_id, messages::types::ResultReady &output);
    void saveOutputYaml(const uint32_t flow_id, const uint8_t stage_id, const messages::types::ResultReady &result);
    void saveOutputBinary(const uint32_t flow_id, const uint8_t stage_id, const uint8_t *buf, const size_t size);
    void log_stats(bool force = false);

private:
    const int SELECT_TIMEOUT_MSEC = 10;
    const int REPORT_INTRVAL_MSEC = 1000;

    friend class irp_data_thread;

    std::string m_broker_uds;
    std::string m_module_name;

    messages::inference::GlobalConfig m_global_config;

    std::string m_dump_path;

    imif::common::rate_limiter m_rate_limiter;

    //statistics and metrics
    uint64_t m_incoming_inference_bytes = 0;
    uint64_t m_incoming_inference_total = 0;
    uint64_t m_inferences_post_processed = 0;
    uint64_t m_total_received_bytes = 0;

    uint32_t m_output_width = 160;
    uint32_t m_output_height = 160;
    std::string m_output_format = "i420"; //output format is fixed to i420

    std::shared_ptr<uint8_t> m_resize_rgb_image_buff = nullptr;
    size_t m_resize_rgb_image_buff_bytes = 0;

    std::ofstream m_output_dump_stream;
    std::unordered_map<uint32_t, std::shared_ptr<IrpPipe>> m_pipes; //mapping pipe_id <-> pipe

    std::chrono::steady_clock::time_point m_last_stats;
    std::chrono::steady_clock::time_point m_start_time;
    std::chrono::steady_clock::time_point m_next_register;
    bool m_enabled = false;
    int32_t m_device_num = -1;

    std::list<messages::types::EventFrameReady> m_ilb_outputs;
    std::map<uint32_t, messages::types::ResultReady> m_latest_valid_output_map; //contains the latest valid IRP output, per flow

    std::shared_ptr<irp_data_thread> m_data_thread = nullptr;

    std::unordered_map<uint32_t, std::shared_ptr<std::ofstream>> m_yaml_results_stream_map;
    std::unordered_map<uint32_t, std::shared_ptr<std::ofstream>> m_blob_results_stream_map;

    std::map<uint32_t, std::map<uint32_t, messages::types::Stage>> m_flows; // key - flow_id -> key - stage_id
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> m_flow2shmkey;
    std::unordered_map<uint32_t, int> m_shmkey_rfc;
    std::unordered_map<uint32_t, uint32_t> m_inf_cfg2shmkey;

    common::event_queue_fd m_event_queue;
    std::shared_ptr<common::event_queue_fd> m_raw_results_queue = nullptr;
};
} // namespace irp
} // namespace imif

#endif
