
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

#ifndef _RESULT_THREAD_H
#define _RESULT_THREAD_H

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_defines.h"
#include "common_logging.h"

#include "mstream_publisher.h"
#include <messages/proto/inference.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/types.pb.h>

#include <unordered_map>

namespace imif {
namespace mstream {

class result_thread : public common::broker_thread {
public:
    result_thread(const std::string broker_uds = "../temp/imif_broker");
    ~result_thread();

    virtual bool post_init() override;
    bool handle_subscribe(uint32_t flow_id, uint32_t stage_id, subscriber *sub);
    bool handle_unsubscribe(uint32_t flow_id, uint32_t stage_id, subscriber *sub);

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;

private:
    void handle_result(messages::types::EventResultReady &result);

    publisher m_publisher;
    std::string m_module_name;
    std::string m_broker_uds_path;
};
} // namespace mstream
} // namespace imif

#endif
