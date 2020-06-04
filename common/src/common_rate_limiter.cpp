
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

#include "common_rate_limiter.h"

#include "easylogging++.h"

using namespace imif::common;

void rate_limiter::set_rate_limit(const uint64_t limit)
{
    m_rate_limit = limit;
    m_skip_rate = m_dropped_frames = 0;
    m_frame_skip_map.clear();
    m_last_update_timestamp = std::chrono::steady_clock::now();
}

bool rate_limiter::check_frame_skip(uint32_t flow_id)
{

    const uint8_t total_bits = sizeof(m_skip_rate) * 8;
    bool skip_frame = (1 << m_frame_skip_map[flow_id]) & m_skip_rate;

    m_frame_skip_map[flow_id] = (m_frame_skip_map[flow_id] + 1) % total_bits;

    return skip_frame;
}

bool rate_limiter::check_frame_skip(const messages::types::FrameInfo &frame_info)
{
    uint32_t flow_id = frame_info.flow().id();
    return check_frame_skip(flow_id);
}

void rate_limiter::update_skip_ratio()
{
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_update_timestamp).count();
    uint64_t fps_limit;

    if (duration < m_duration_ms) {
        //too soon
        return;
    }

    if (m_rate_limit < 0) {
        //rate limit is off
        return;
    } else if (m_rate_limit == 0) {
        //automatic rate limit
        if (m_dropped_frames > 0) {
            //we are dropping frames, the fps limit must be limited by the total incoming frames minus the dropped frames
            fps_limit = m_frame_counter - m_dropped_frames;
        } else {
            //no frames were dropped, don't limit
            fps_limit = UINT32_MAX;
        }
    } else {
        //manual rate limit
        fps_limit = m_rate_limit;
    }

    int num_of_flows = m_frame_skip_map.size();
    uint64_t expected_fps = m_frame_counter * std::max(1, (1000 / (int)duration));
    const uint8_t total_bits = sizeof(m_skip_rate) * 8;

    m_skip_rate = 0;
    m_dropped_frames = 0;
    m_frame_counter = 0;
    m_last_update_timestamp = std::chrono::steady_clock::now();

    if (num_of_flows == 0) {
        //no streams at all, nothing to limit
        return;
    } else {
        //calculating the per-stream expected fps
        expected_fps /= num_of_flows;
        fps_limit /= num_of_flows;
    }

    for (auto &it : m_frame_skip_map) {
        it.second = 0;
    }

    if (fps_limit == 0 || fps_limit >= expected_fps) {

        //the rate is lower than the limit (or without limit), do nothing

    } else {
        const float RESOLUTION = total_bits * 1.0;
        float ratio = 1.0 * (expected_fps - fps_limit) / expected_fps;
        if (ratio < 0.1) {
            ratio = 0.1;
        }

        uint64_t step = (int)(round(RESOLUTION / (ratio * RESOLUTION)));
        step = std::max((int)step, 1);

        if (step == 1) {
            uint64_t step = (int)(round(RESOLUTION - (ratio * RESOLUTION)));
            m_skip_rate = uint64_t(-1);
            for (uint64_t i = 0; i < total_bits; i += step) {
                m_skip_rate &= ~uint64_t((uint64_t)1 << i);
            }
        } else {

            for (uint64_t i = 0; i < total_bits; i += step) {
                m_skip_rate |= uint64_t((uint64_t)1 << i);
            }
        }
    }

    LOG(DEBUG) << "for fps_limit=" << fps_limit << " --> skip rate= 0x" << std::hex << m_skip_rate << std::dec;
}
