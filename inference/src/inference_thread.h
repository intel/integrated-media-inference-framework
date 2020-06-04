
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

#ifndef _INFERENCE_THREAD_H
#define _INFERENCE_THREAD_H

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_logging.h"
#include "common_message.h"

#include "ilb/ilb_thread.h"
#include "common_event_queue_fd.h"
#include "irp/irp_thread.h"

#include <chrono>
#include <unordered_map>

#include <messages/proto/mgmt.pb.h>

namespace imif {
namespace inference {

class InferenceThread : public common::broker_thread {
public:
    InferenceThread(const std::string broker_uds, imif::common::logging *pLogger);
    ~InferenceThread();

protected:
    virtual bool post_init() override;
    virtual bool before_select() override;
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;

private:
    void reset();
    bool global_config(const messages::mgmt::GlobalConfig &global_config);

    bool add_config(const messages::mgmt::AddConfig &config);
    bool add_flow(const messages::mgmt::AddFlow &flow);

    bool remove_config(messages::mgmt::RemoveConfig &request);
    bool remove_flow(messages::mgmt::RemoveFlow &request);

    void handle_enable(messages::mgmt::Enable &request);

    void logStats();

    bool receive_chunk(messages::mgmt::SendChunk &send_chunk);

private:
    const int SELECT_TIMEOUT_MSEC = 2000;
    const int STATISTICS_INTRVAL_MSEC = 1000;
    const uint AGGREGATED_STATISTICS = 10; //will report average stats every AGGREGATED_STATISTICS*STATISTICS_INTRVAL_MSEC

    // ILb management and module configuration //
    std::string m_broker_path;
    std::string m_module_name;

    std::chrono::steady_clock::time_point m_next_register;
    bool m_registered = false;
    bool m_enabled = false;

    messages::mgmt::GlobalConfig m_global_config;

    struct sInferenceConfig {
        std::shared_ptr<ilb::IlbThread> ilb_thread = nullptr;
        std::shared_ptr<irp::IrpThread> irp_thread = nullptr;
        std::shared_ptr<common::event_queue_fd> raw_results_queue;
        uint32_t rfc = 0;
    };

    //std::shared_ptr<irp::IrpThread> m_irp_thread;
    std::unordered_map<uint32_t, uint32_t> m_config_to_device;

    std::unordered_map<uint32_t, sInferenceConfig> m_inference_threads;

    // Ilb logging
    imif::common::logging *m_pLogger;
    std::chrono::steady_clock::time_point m_statistics_report_timestamp;
};

} // namespace inference
} // namespace imif

#endif
