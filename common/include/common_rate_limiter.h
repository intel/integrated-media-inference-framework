
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

#ifndef __RATE_LIMITER_H_
#define __RATE_LIMITER_H_

#include <chrono>
#include <math.h>
#include <memory>
#include <messages/proto/types.pb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

namespace imif {
namespace common {

class rate_limiter {
public:
    ///
    /// @brief sets the rate limit
    ///
    void set_rate_limit(const uint64_t limit);

    ///
    /// @brief gets the rate limit
    ///
    uint64_t get_rate_limit() { return m_rate_limit; }

    ///
    /// @brief checks if a certain frame is to be skipped
    ///
    bool check_frame_skip(const messages::types::FrameInfo &frame_info);
    bool check_frame_skip(uint32_t flow_id);

    ///
    /// @brief updates the skip ratio bitmap according to the current rate
    ///
    void update_skip_ratio();

    ///
    /// @brief adds/subtracts to/from the number of incoming frames.
    ///
    void update_dropped_frames(const int frames) { m_dropped_frames += frames; }

    ///
    /// @brief adds/subtracts to/from the number of dropped frames.
    ///
    void update_frame_counter(const int frames) { m_frame_counter += frames; }

private:
    // the rate limit, in units of frames per second.
    int64_t m_rate_limit = 0;

    // a bitmap containing the skip ratio. the more bits - the more accuracy in the ration between skipped and unskipped frames.
    uint64_t m_skip_rate = 0;

    //the last timestamp in which we calculated the skip ratio
    std::chrono::steady_clock::time_point m_last_update_timestamp;

    //mapping between frame_info <-> skip_frame_index
    std::unordered_map<uint32_t, int> m_frame_skip_map;

    //counts the number of incoming frames
    uint64_t m_frame_counter = 0;

    //counts the dropped frames
    uint64_t m_dropped_frames = 0;

    //specifies the duration in which to calculate the skip ratio, in units of ms
    const int64_t m_duration_ms = 100;
};
} // namespace common
} // namespace imif

#endif //__RATE_LIMITER_H_
