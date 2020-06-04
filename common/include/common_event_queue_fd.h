
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

#ifndef _EVENT_QUEUE_FD_H_
#define _EVENT_QUEUE_FD_H_

#include "common_event_queue.h"

namespace imif {
namespace common {

class event_queue_fd : event_queue {
public:
    event_queue_fd();
    virtual ~event_queue_fd();

    void clear() { event_queue::clear(); }
    int get_events_fd() { return m_events_fd; }
    bool push_event(uint32_t opcode, const google::protobuf::Message &msg) override;
    bool push_event(uint32_t opcode) override;
    std::shared_ptr<event_t> pop_event(bool block = true) override;

private:
    int m_events_fd = -1;
};

} // namespace common
} // namespace imif

#endif // _EVENT_QUEUE_H_
