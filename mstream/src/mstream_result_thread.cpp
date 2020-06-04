
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

#include "mstream_result_thread.h"

using namespace imif;
using namespace common;
using namespace mstream;

result_thread::result_thread(const std::string broker_uds)
    : broker_thread("RESULT_THREAD", broker_uds), m_module_name("mstream"), m_broker_uds_path(broker_uds)
{
}

result_thread::~result_thread() { LOG(TRACE) << "destructor()"; }

void result_thread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    should_stop = true;
}

bool result_thread::post_init()
{
    // Register to bus messages

    subscribe({messages::enums::Opcode::INFERENCE_RESULTS_READY});

    return true;
}
bool result_thread::handle_subscribe(uint32_t flow_id, uint32_t stage_id, subscriber *sub)
{
    m_publisher.subscribe(sub, flow_id, stage_id);
    return true;
}
bool result_thread::handle_unsubscribe(uint32_t flow_id, uint32_t stage_id, subscriber *sub)
{
    m_publisher.unsubscribe(sub, flow_id, stage_id);
    return true;
}

bool result_thread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
    case messages::enums::Opcode::INFERENCE_RESULTS_READY: {
        messages::types::EventResultReady message;
        if (!message.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing INFERENCE_RESULTS_READY";
            return false;
        }
        handle_result(message);
    } break;
    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
    } break;
    }
    return true;
}

void result_thread::handle_result(messages::types::EventResultReady &message)
{
    for (auto &result : message.results()) {
        auto flow_id = result.frame_info().flow().id();
        for (auto stage_id : result.frame_info().flow().stage_id()) {
            m_publisher.publish(flow_id, stage_id, result);
        }
    }
}

publisher::publisher() { m_subscribed.clear(); }

void publisher::subscribe(subscriber *sub, uint32_t flow_id, uint32_t stage_id)
{
    LOG(INFO) << "subscribe to flow_id " << flow_id;
    m_subscribed[flow_id][stage_id].insert(sub);
}

void publisher::unsubscribe(subscriber *sub, uint32_t flow_id, uint32_t stage_id)
{
    auto subscribed_it = m_subscribed.find(flow_id);
    if (subscribed_it == m_subscribed.end()) {
        return;
    }
    auto subscribed_it2 = subscribed_it->second.find(stage_id);
    if (subscribed_it2 == subscribed_it->second.end()) {
        return;
    }
    subscribed_it2->second.erase(sub);
}

void publisher::publish(uint32_t flow_id, uint32_t stage_id, const messages::types::ResultReady &message)
{
    auto subscribed_it = m_subscribed.find(flow_id);
    if (subscribed_it == m_subscribed.end()) {
        return;
    }
    for (subscriber *sub : subscribed_it->second[stage_id]) {
        sub->publish_event(flow_id, message);
    }
    for (subscriber *sub : subscribed_it->second[-1]) {
        sub->publish_event(flow_id, message);
    }
}
