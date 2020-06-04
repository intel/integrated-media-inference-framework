
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

#pragma once

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_mem_manager.h"

#include <chrono>
#include <unordered_map>

#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>

namespace imif {
namespace mstream {

class ImageLoadThread : public common::thread_base {
public:
    ImageLoadThread(const messages::types::Source &source, const std::string broker_uds = "../temp/imif_broker");
    ~ImageLoadThread();

    bool add_flow(const messages::types::Flow &flow, uint32_t batch_size);
    void enable(bool enable = true) { m_enabled = enable; }
    void start_source(bool start = true) { m_started = start; }
    bool get_started_source() { return m_started; }

    uint64_t sent_bytes() { return m_sent_bytes; }
    void reset_stats();

protected:
    virtual void on_thread_stop() override;
    virtual bool init() override;
    virtual bool work() override;

private:
    void set_batch_size(int batch_size);
    bool add_source(const messages::types::Source &source);

private:
    const messages::types::Source m_source;

    std::string m_broker_uds;
    std::shared_ptr<common::SocketClient> m_broker_socket = nullptr;

    // configuration //
    std::ifstream m_input_stream;
    std::string m_stream_format = "";

    bool m_enabled = false;
    bool m_started = false;

    std::shared_ptr<imif::common::shmem_pool> m_pool = nullptr;

    size_t m_width = 0;
    size_t m_height = 0;
    size_t m_image_size = 0;
    uint64_t m_frame_num = 0;
    uint64_t m_frame_rate = 0;
    uint64_t m_frame_rate_us =
        0; //The period (in usec) in which the imageloader will push frames to the ILB. if 0, push without delaying
    uint64_t m_bps = 0;
    uint64_t m_bps_sleep_us = 0;
    std::chrono::steady_clock::time_point m_prev_frame_timestamp = std::chrono::steady_clock::now();

    uint32_t m_source_id = 0;
    int m_batch_size = 1;
    uint64_t m_bytes_to_send = 0;
    messages::types::Flow m_flow;

    bool m_load_to_ram = false;
    uint64_t m_max_ram_size = 0;
    uint64_t m_ram_size = 0;
    char *m_buffered_file = nullptr;
    uint64_t m_read_offset = 0; // used only to read from memory

    uint64_t m_sent_bytes = 0;
};
} // namespace mstream
} // namespace imif
