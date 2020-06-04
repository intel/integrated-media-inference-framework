
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

#include "common_event_queue_fd.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <easylogging++.h>

using namespace imif::common;

event_queue_fd::event_queue_fd()
{
    if ((m_events_fd = eventfd(0, EFD_SEMAPHORE)) < 0) {
        LOG(FATAL) << "Failed creating eventfd: " << strerror(errno);
    }
}

event_queue_fd::~event_queue_fd()
{
    if (m_events_fd != -1) {
        close(m_events_fd);
        m_events_fd = -1;
    }
}

bool event_queue_fd::push_event(uint32_t opcode, const google::protobuf::Message &msg)
{
    event_queue::push_event(opcode, msg);

    // Increment the eventfd counter by 1
    uint64_t counter = 1;
    if (write(m_events_fd, &counter, sizeof(counter)) < 0) {
        LOG(ERROR) << "Failed updating eventfd counter: " << strerror(errno);
        return false;
    }
    return true;
}

bool event_queue_fd::push_event(uint32_t opcode)
{
    event_queue::push_event(opcode);

    // Increment the eventfd counter by 1
    uint64_t counter = 1;
    if (write(m_events_fd, &counter, sizeof(counter)) < 0) {
        LOG(ERROR) << "Failed updating eventfd counter: " << strerror(errno);
        return false;
    }
    return true;
}

std::shared_ptr<event_t> event_queue_fd::pop_event(bool block)
{
    uint64_t counter = 0;
    if (read(m_events_fd, &counter, sizeof(counter)) < 0) {
        LOG(ERROR) << "Failed reading eventfd counter: " << strerror(errno);
        return nullptr;
    }

    // Pop an event from the queue
    auto event = event_queue::pop_event(block);

    if (!event || !counter) {
        LOG(WARNING) << "pop_event() called by the event queue pointer is " << event << " and/or eventfd counter = " << counter;
    }

    return event;
}
