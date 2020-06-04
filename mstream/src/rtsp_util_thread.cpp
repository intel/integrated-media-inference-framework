
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

#include "easylogging++.h"

#include "rtsp_util_thread.h"

using namespace imif;
using namespace mstream;

bool rtsp_util_thread::init() { return true; }

void rtsp_util_thread::on_thread_stop() { m_queue_events.clear(); }

bool rtsp_util_thread::work()
{
    if (should_stop)
        return true;
    sMstEvent event = m_queue_events.pop();

    LOG(INFO) << "Recieved event type " << uint32_t(event.type);

    if (event.type == eMstEvents::STOP_THREAD || should_stop) {
        should_stop = true;
        return true;
    }

    auto rtsp_client = event.rtsp_client;
    if (!rtsp_client) {
        LOG(ERROR) << "Failed getting rtsp client for event " << uint32_t(event.type);
        return false;
    }

    switch (event.type) {
    case eMstEvents::SETUP_STREAM: {
        LOG(DEBUG) << "Setup stream " << rtsp_client->getID();
        rtsp_client->setupStream(true);
    } break;
    case eMstEvents::START_STREAM: {
        LOG(DEBUG) << "Start stream " << rtsp_client->getID();
        rtsp_client->setStarted(true);
    } break;
    case eMstEvents::PLAY_STREAM: {
        if (rtsp_client->getStarted() && !rtsp_client->getPlaying()) {
            LOG(DEBUG) << "Play stream " << rtsp_client->getID();
            rtsp_client->startStream();
        }
    } break;
    case eMstEvents::PAUSE_STREAM: {
        if (rtsp_client->getStarted() && rtsp_client->getPlaying()) {
            LOG(DEBUG) << "Pause stream " << rtsp_client->getID();
            rtsp_client->pauseStream();
        }
    } break;
    case eMstEvents::TEAR_DOWN_STREAM: {
        LOG(DEBUG) << "Tear down stream " << rtsp_client->getID();
        rtsp_client->tearDown();
        rtsp_client->closeDumpFile();
    } break;
    default:
        LOG(ERROR) << "Unknown event type " << uint32_t(event.type);
        break;
    }

    return true;
}
