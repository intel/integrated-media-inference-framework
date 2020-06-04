
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

#ifndef _RTSP_UTIL_THREAD_H
#define _RTSP_UTIL_THREAD_H

#include <functional>

#include "common_thread_base.h"
#include "common_thread_safe_queue.h"

#include "rtsp_client.h"

namespace imif {
namespace mstream {

enum class eMstEvents {
    INVALID = 0,
    SETUP_STREAM,
    START_STREAM,
    PLAY_STREAM,
    PAUSE_STREAM,
    STOP_STREAM,
    TEAR_DOWN_STREAM,
    STOP_THREAD,
};

struct sMstEvent {
    eMstEvents type = eMstEvents::INVALID;
    std::shared_ptr<RtspClientInst> rtsp_client = nullptr;

    sMstEvent() {}
    sMstEvent(eMstEvents type_, std::shared_ptr<RtspClientInst> rtsp_client_) : type(type_), rtsp_client(rtsp_client_) {}
};

class rtsp_util_thread : public common::thread_base {
public:
    rtsp_util_thread() {}
    bool push_event(sMstEvent &event) { return m_queue_events.push(event); }
    bool push_event(sMstEvent event) { return m_queue_events.push(event); }
    bool push_event(eMstEvents type, std::shared_ptr<RtspClientInst> rtsp_client)
    {
        return push_event(sMstEvent(type, rtsp_client));
    }

protected:
    virtual bool init() override;
    virtual bool work() override;
    virtual void on_thread_stop() override;

private:
    common::thread_safe_queue<sMstEvent> m_queue_events;
};
} // namespace mstream
} // namespace imif

#endif
