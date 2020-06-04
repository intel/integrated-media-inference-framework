
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

#ifndef _MDECODE_THREAD_H
#define _MDECODE_THREAD_H

#include "easylogging++.h"

#include "common_broker_thread.h"
#include "common_defines.h"
#include "common_logging.h"
#include "common_mem_manager.h"
#include "common_thread_safe_queue.h"

#include "mfx_samples_config.h"
#include "stream_pipeline_decode.h"

#include <messages/proto/enums.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>
#include <messages/proto/types.pb.h>

#include <chrono>
#include <unordered_map>

#define DEFAULT_IMAGE_SIZE (5 * 1024 * 1024)
#define NUMBER_DECODED_IMAGES (10)

#define MSG_MIN_BUFF_SIZE 1024

namespace imif {
namespace mdecode {
enum eSTSreadBSdata {
    STS_READ_NO_ERROR = 0x1,
    STS_READ_MORE_DATA = 0x2,
    STS_READ_RUN_DECODER = 0x4,
    STS_READ_ERROR = 0x8,
    STS_READ_FATAL = 0x10
};

enum eSTSrunDecoder {
    STS_DEC_NO_ERROR = 0x1,
    STS_DEC_MORE_DATA = 0x2,
    STS_DEC_MORE_SURFACE = 0x4,
    STS_DEC_BUSY = 0x8,
    STS_DEC_DIDNT_CONSUME = 0x10,
    STS_DEC_FATAL = 0x20,
};

struct sStreamStats {
    size_t bytes_recieved;
    size_t total_bytes_recieved;
    size_t bytes_in;
    size_t total_bytes_in;
    uint64_t frames;
    uint64_t total_frames;
    uint64_t dropped_frames;
    uint64_t total_dropped_frames;
    std::chrono::steady_clock::time_point first_frame_timestamp;
    std::chrono::steady_clock::time_point last_frame_timestamp;
    sStreamStats()
    {
        bytes_recieved = 0;
        total_bytes_recieved = 0;
        bytes_in = 0;
        total_bytes_in = 0;
        frames = 0;
        total_frames = 0;
        dropped_frames = 0;
        total_dropped_frames = 0;
    }
};
struct sStreamDecInst {
    sStreamInputParams params;
    std::unique_ptr<CStreamDecodingPipeline> pipeline;
    std::unique_ptr<CSmplYUVWriter> frame_writer;
    sStreamStats stats;
    bool low_latency;
    sStreamDecInst()
    {
        frame_writer = nullptr;
        low_latency = false;
    }
};
class mdecode_image_thread : public common::thread_base {
public:
    mdecode_image_thread(std::string broker_uds_path, const messages::types::Stage &stage,
                         const std::shared_ptr<imif::common::shmem_pool> &pool, const sStreamInputParams &params);
    void push_event(const messages::types::FrameReady &frame_ready);

protected:
    virtual bool init() override;
    virtual bool work() override;
    virtual void on_thread_stop() override;

private:
    std::string m_broker_uds;
    std::shared_ptr<imif::common::Socket> m_broker_socket = nullptr;
    void deliver_frame(mfxFrameSurface1 *frame, uint32_t flow_id, uint64_t client_context);

    common::thread_safe_queue<messages::types::FrameReady> m_event_queue;
    messages::types::Stage m_stage;

    std::shared_ptr<common::shmem_pool> m_pool;
    sStreamInputParams m_params;
    std::shared_ptr<sStreamDecInst> m_dec = nullptr;
    messages::types::EventFrameReady m_agg_request;
    int m_batch_size = 1;
    int m_frame_num = 0;
};
class MDecodeThread : public common::broker_thread {
public:
    MDecodeThread(const std::string broker_uds = "../temp/imif_broker", imif::common::logging *pLogger = nullptr);
    ~MDecodeThread();

    virtual bool post_init() override;
    virtual bool before_select() override;
    virtual bool after_select(bool timeout) override;
    static int runDecoder(std::shared_ptr<sStreamDecInst> pDec);

protected:
    virtual void on_thread_stop() override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd, messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override;
    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override;
    virtual bool socket_disconnected(std::shared_ptr<common::Socket> sd) override;

private:
    void reset();
    void forceCloseSocket(std::shared_ptr<common::Socket> sd);

    bool setDecoderParams(sStreamInputParams &params, messages::mdecode::Config config);

    bool global_config(const messages::mgmt::GlobalConfig global_config);

    bool add_config(const messages::types::Config &config);
    bool add_flow(const messages::types::Flow &flow);

    bool remove_config(uint32_t config_id);
    bool remove_flow(uint32_t flow_id, bool skip_erase = false);

    bool decode_flow(messages::mstream::EventBsReady &decode);
    bool decode_flow(uint32_t flow_id, std::shared_ptr<common::shmem_buff> buff = nullptr,
                     messages::mstream::EventBsReady decode = messages::mstream::EventBsReady());

    void deliver_frame(mfxFrameSurface1 *frame, uint32_t flow_id, uint64_t client_context);
    void log_stats(bool force = false, bool full_report = false, bool periodic = true);

    void handle_enable();
    void handle_disable();

    template <typename T> void updateConfig(std::string param, T &var);

    size_t copyBsData(std::shared_ptr<sStreamDecInst> pDec, uint8_t *data, size_t payload_len);

private:
    const int SELECT_TIMEOUT_MSEC = 10;
    const int WORK_REPORT_INTRVAL_MSEC = 2000;
    const int MDECODE_DECODED_FRAME_COUNT = 100;

    // configuration //
    std::string m_module_name;

    messages::mdecode::GlobalConfig m_global_config;
    std::string m_dump_path;

    std::unordered_map<uint32_t, messages::mdecode::Config> m_configs; // key - config_id

    std::unordered_map<uint64_t, std::shared_ptr<sStreamDecInst>>
        m_stream_decoder_vec; // key -flow_id// key - source_id + config_id

    struct sSourceConfig {
        uint32_t source_id = 0;
        uint32_t config_id = 0;
        uint32_t stage_id = 0;
    };
    std::unordered_map<uint32_t, sSourceConfig> m_flows;               // key = flow_id, value = source_id + config_id
    std::unordered_map<uint32_t, messages::types::Stage> m_flow_stage; // key = flow_id

    std::unordered_map<uint64_t, std::shared_ptr<imif::common::shmem_pool>> m_pool_input_map; // key - source_id

    std::chrono::steady_clock::time_point m_next_register;
    bool m_registered = false;
    bool m_enabled = false;
    int m_batch_size = 1;

    std::chrono::steady_clock::time_point m_work_last_report_timestamp;
    std::unordered_map<uint64_t, std::shared_ptr<imif::common::shmem_pool>> m_pool_output_map;
    std::unordered_map<uint64_t, std::shared_ptr<mdecode_image_thread>> m_image_threads; // key = config_id

    std::string m_broker_uds_path;
    imif::common::logging *m_pLogger;
    messages::types::EventFrameReady m_agg_request;
};
} // namespace mdecode
} // namespace imif

#endif
