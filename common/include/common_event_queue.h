
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

#ifndef EVENT_QUEUE_H_
#define EVENT_QUEUE_H_

#include "common_thread_safe_queue.h"
#include <messages/proto/broker_control.pb.h>

namespace imif {
namespace common {

struct event_t {
    uint32_t opcode = 0;
    uint32_t id = 0;
    std::shared_ptr<void> msg = nullptr;
    size_t msg_len = 0;
};

class event_queue {
public:
    event_queue() { m_queue.clear(); }

    void clear() { m_queue.clear(); }
    virtual bool push_event(uint32_t opcode, const google::protobuf::Message &msg);
    virtual bool push_event(uint32_t opcode);
    virtual std::shared_ptr<event_t> pop_event(bool block = false);

private:
    thread_safe_queue<std::shared_ptr<event_t>> m_queue;
};

} // namespace common
} // namespace imif

#endif // EVENT_QUEUE_H_
