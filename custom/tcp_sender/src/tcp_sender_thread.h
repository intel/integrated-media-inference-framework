
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

#ifndef _TCP_SENDER_THREAD_H
#define _TCP_SENDER_THREAD_H

#include "common_broker_thread.h"
#include "common_event_queue_fd.h"
#include "common_mem_manager.h"
#include "common_rate_limiter.h"

#include <messages/proto/inference.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/types.pb.h>

#include "common_logging.h"

#include <set>
#include <unordered_map>

#include "opencv2/core/core_c.h"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/imgproc/types_c.h"
#include "opencv2/objdetect/objdetect.hpp"

namespace imif {
namespace sender {

struct sOutput {
    std::shared_ptr<common::shmem_buff> frame = nullptr;
    messages::types::FrameInfo frame_info;
    messages::types::ResultReady result;
    bool result_valid = false;
    uint32_t subframe_number = 0;
    bool frame_valid = false;
    std::chrono::steady_clock::time_point timestamp;
};

class tcp_sender_thread : public common::broker_thread {
public:
    tcp_sender_thread(const std::string broker_uds, imif::common::logging *pLogger);
    ~tcp_sender_thread();

    virtual bool post_init() override;
    virtual bool before_select() override;

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override;

    virtual bool socket_disconnected(std::shared_ptr<common::Socket> sd) override;
    virtual bool socket_connected(std::shared_ptr<common::Socket> sd) override;
    virtual bool socket_error(std::shared_ptr<common::Socket> sd) override;

private:
    void reset();

    bool global_config(const messages::mgmt::GlobalConfig global_config);

    bool add_config(const messages::types::Config &config);
    bool add_flow(const messages::types::Flow &flow);

    bool remove_config(uint32_t config_id);
    bool remove_flow(uint32_t flow_id);

    void handle_enable();
    void handle_disable();

    bool is_known_flow(const messages::types::FlowEvent &flow);

    std::shared_ptr<uint8_t> alloc_shared_ptr_buffer(ssize_t size, std::string name);

    void resize_frame_i420(uint8_t *input_ptr, messages::types::ResultReady &output, const size_t src_height,
                           const size_t src_width);
    void convert_and_resize_nv12_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output);
    void convert_and_resize_bgra_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output);
    void convert_and_resize_rgb_to_i420(uint8_t *input_ptr, messages::types::ResultReady &output);

    void clearOutputMap();
    void forceCloseSocket(std::shared_ptr<common::Socket> sd);

    void process_event_frame_ready(const messages::types::FrameReady &frame);
    void storeOutput(messages::types::EventResultReady &output);
    void storeOutput(const messages::types::FrameReady &frame_ready);

    void sendOutput(uint32_t flow_id);

    void log_stats(bool force = false);
    void periodic_cleanup();

private:
    const int SELECT_TIMEOUT_MSEC = 10;
    const int REPORT_INTRVAL_MSEC = 1000;
    const int FRAME_RATE_INTRVAL_MSEC = 1000;
    const int CLEANUP_INTRVAL_MSEC = 1000;
    const uint32_t AGING_INTERVAL_MSEC = 5000;
    const uint32_t INFERENCE_STALL_INTERVAL_MSEC = 5000;

    std::chrono::steady_clock::time_point m_next_register = std::chrono::steady_clock::now();
    bool m_registered = false;

    std::string m_module_name;

    std::shared_ptr<common::SocketServer> m_tcp_server_socket = nullptr;

    imif::common::rate_limiter m_rate_limiter;

    //statistics and metrics
    uint64_t m_incoming_inference_total = 0;
    uint64_t m_incoming_frame_bytes = 0;
    uint64_t m_incoming_frame_total = 0;
    uint64_t m_sent_bytes = 0;
    uint64_t m_total_received_bytes = 0;
    uint64_t m_total_sent_bytes = 0;
    uint64_t m_sent_frames = 0;
    uint64_t m_skipped_frames = 0;
    uint64_t m_dropped_frames = 0;

    int32_t m_output_fps = -1;
    uint32_t m_output_width = 160;
    uint32_t m_output_height = 160;
    std::string m_output_format = "i420"; //output format is fixed to i420

    std::shared_ptr<uint8_t> m_resize_out_buff = nullptr;
    ssize_t m_resize_out_buff_bytes = 0;
    std::shared_ptr<uint8_t> m_resize_rgb_image_buff = nullptr;
    ssize_t m_resize_rgb_image_buff_bytes = 0;
    std::shared_ptr<uint8_t> m_resize_i420_image_buff = nullptr;
    ssize_t m_resize_i420_image_buff_bytes = 0;

    std::chrono::steady_clock::time_point m_last_stats= std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point m_next_frame_rate_update = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point m_start_time = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point m_last_cleanup = std::chrono::steady_clock::now();

    bool m_enabled = false;

    std::shared_ptr<common::Socket> m_ui_sd = nullptr;

    std::map<uint32_t, std::map<uint64_t, sOutput>> m_output_map;

    std::map<uint32_t, std::map<uint64_t, std::chrono::steady_clock::time_point>> m_deleted_frames;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> m_last_inference_result = {};

    std::list<uint32_t> m_output_stream_flow_ids = {};

    std::unordered_map<uint32_t, uint32_t> m_flow2stageid; // key = flow_id, value = stage_id

    std::unordered_map<uint32_t, std::set<uint32_t>> m_flow2shmkey;

    imif::common::logging *m_pLogger;
};
} // namespace sender
} // namespace imif

#endif
