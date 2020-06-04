
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

#include "common_event_queue.h"

#include <easylogging++.h>

// Allocate a char array wrapped in a shared_ptr
#define ALLOC_SMART_BUFFER(size)                                                                                                   \
    std::shared_ptr<char>(new char[size], [](char *obj) {                                                                          \
        if (obj)                                                                                                                   \
            delete[] obj;                                                                                                          \
    })

using namespace imif::common;

bool event_queue::push_event(uint32_t opcode, const google::protobuf::Message &msg)
{
    auto event_buff = ALLOC_SMART_BUFFER(msg.ByteSizeLong());
    if (!event_buff) {
        LOG(FATAL) << "Failed allocating memory for event " << opcode;
        return false;
    }

    if (!msg.SerializeToArray(event_buff.get(), msg.ByteSizeLong())) {
        LOG(ERROR) << "Failed push!";
        return false;
    }

    auto event = std::make_shared<event_t>();
    event->msg = event_buff;
    event->opcode = opcode;
    event->msg_len = msg.ByteSizeLong();

    m_queue.push(event);

    return true;
}

bool event_queue::push_event(uint32_t opcode)
{
    auto event = std::make_shared<event_t>();
    event->opcode = opcode;
    m_queue.push(event);

    return true;
}

std::shared_ptr<event_t> event_queue::pop_event(bool block)
{
    // Pop an event from the queue
    return m_queue.pop(block);
}
