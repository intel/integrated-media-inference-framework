
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

#include "mdecode_thread.h"

using namespace imif;
using namespace common;
using namespace mdecode;

bool WriteNextFrame(mfxFrameSurface1 *pSurface, uint8_t *destPtr);
bool WriteNextFrameI420(mfxFrameSurface1 *pSurface, uint8_t *destPtr);

mdecode_image_thread::mdecode_image_thread(std::string broker_uds_path, const messages::types::Stage &stage,
                                           const std::shared_ptr<imif::common::shmem_pool> &pool, const sStreamInputParams &params)
    : m_broker_uds(broker_uds_path), m_stage(stage), m_pool(pool), m_params(params)
{
}

void mdecode_image_thread::push_event(const messages::types::FrameReady &frame_ready) { m_event_queue.push(frame_ready); }

bool mdecode_image_thread::init()
{
    LOG(TRACE) << "mdecode_image_thread initializing";
    LOG(DEBUG) << "m_broker_uds " << m_broker_uds;
    m_broker_socket = std::make_shared<common::SocketClient>(m_broker_uds);
    if (!m_broker_socket) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds;
        return false;
    }
    const auto error_msg = m_broker_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds << " [ERROR: " << error_msg << "]";
        m_broker_socket.reset();
        return false;
    }
    LOG(DEBUG) << "mdecode_image_thread finished initializing";
    return true;
}

void mdecode_image_thread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    m_event_queue.clear();
    m_pool = nullptr; //<-- frees the shared memory pool
    m_broker_socket.reset();

    should_stop = true;
}

bool mdecode_image_thread::work()
{
    messages::types::FrameReady frame_ready = m_event_queue.pop();
    LOG(DEBUG) << "popped from queue: frame_ready:" << frame_ready;

    m_dec = std::make_shared<sStreamDecInst>();
    if (!m_dec) {
        LOG(FATAL) << "Failed allocating decoder";
        return false;
    }

    m_dec->params = m_params;

    m_dec->pipeline = make_unique<CStreamDecodingPipeline>();
    if (!m_dec->pipeline) {
        LOG(FATAL) << "Failed allocating pipline";
        return false;
    }

    auto sts = m_dec->pipeline->InitialInit(&m_params, frame_ready.frame_info().frame().client_context());
    if (sts != MFX_ERR_NONE) {
        LOG(ERROR) << "pipeline.InitialInit() failed --> " << StatusToString(sts);
        return false;
    }

    m_dec->pipeline->SetDeliverDecodedFrameCLBK(
        std::bind(&mdecode_image_thread::deliver_frame, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

    auto frame_buff = frame_ready.buff();

    auto pool = common::shmem_buff_factory::get_shmem_pool(frame_buff.shmkey(), frame_buff.shmsize());
    if (!pool) {
        LOG(ERROR) << "Can't get shm_pool for key=" << int(frame_buff.shmkey());
        return false;
    }

    auto buff = std::make_shared<shmem_buff>(pool, frame_buff);
    if (!buff) {
        LOG(ERROR) << "Failed getting shmem buff";
        return false;
    }

    uint8_t *data_ptr = buff->ptr();
    size_t payload_len = 0;
    payload_len = buff->used_size() ? buff->used_size() : buff->buff_size();

    auto pBS = m_dec->pipeline->GetBS();
    int ret_sts;
    pBS->Data = data_ptr;
    pBS->DataLength = payload_len;
    pBS->DataOffset = 0;

    ret_sts = MDecodeThread::runDecoder(m_dec);

    pBS->DataLength = 0;
    pBS->Data = nullptr;

    if (ret_sts & STS_DEC_FATAL) {
        LOG(ERROR) << "runDecoder returned STS_DEC_FATAL";
        return false;
    } else if (ret_sts & STS_DEC_DIDNT_CONSUME) {
        LOG(ERROR) << "runDecoder returned STS_DEC_DIDNT_CONSUME";
        return false;
    } else if (ret_sts & STS_DEC_BUSY) {
        LOG(ERROR) << "runDecoder returned STS_DEC_BUSY";
        return false;
    }

    m_dec.reset();
    return true;
}

void mdecode_image_thread::deliver_frame(mfxFrameSurface1 *frame, uint32_t flow_id, uint64_t client_context)
{
    if (m_dec == nullptr) {
        LOG(ERROR) << "Can't find m_decoder for flow: " << flow_id;
        return;
    }

    if (!m_pool) {
        LOG(FATAL) << "no pool for flow: " << flow_id;
        return;
    }

    m_dec->stats.first_frame_timestamp = std::chrono::steady_clock::now();
    m_dec->stats.frames++;

    LOG(DEBUG) << "==> Deliver frame " << m_frame_num << " flow=" << flow_id;
    if (m_dec->frame_writer) {
        mfxStatus sts =
            m_dec->params.outI420 ? m_dec->frame_writer->WriteNextFrameI420(frame) : m_dec->frame_writer->WriteNextFrame(frame);
        if (MFX_ERR_NONE != sts) {
            LOG(ERROR) << "Failed to write frame for flow=" << flow_id;
        }
    }

    uint64_t width;
    uint64_t height;

    if (frame->Info.CropH > 0 && frame->Info.CropW > 0) {
        width = frame->Info.CropW;
        height = frame->Info.CropH;
    } else {
        width = frame->Info.Width;
        height = frame->Info.Height;
    }

    size_t frameBytes = (width * height);
    if (m_dec->params.videoFourcc == MFX_FOURCC_NV12) {
        frameBytes = frameBytes + (frameBytes >> 1);
    } else if (m_dec->params.videoFourcc == MFX_FOURCC_I420) {
        frameBytes = frameBytes + (2 * (frameBytes >> 2));
    } else if (m_dec->params.videoFourcc == MFX_FOURCC_RGB4) {
        frameBytes = frameBytes * 4;
    }

    if (m_pool->get_consecutive_free() < frameBytes) {
        LOG(WARNING) << "Dropping frame! - There is not enough shmem space to allocate buff";
        m_dec->stats.dropped_frames++;
        return;
    }
    // allocate new buff
    auto current_buff = m_pool->alloc_buff(frameBytes);
    if (!current_buff) {
        LOG(ERROR) << "Failed allocating new buff";
        m_dec->stats.dropped_frames++;
        return;
    }

    uint8_t *ptr = (uint8_t *)current_buff->ptr();

    bool sts = m_dec->params.outI420 ? WriteNextFrameI420(frame, ptr) : WriteNextFrame(frame, ptr);
    if (!sts) {
        LOG(ERROR) << "Failed copying frame";
        return;
    }

    auto efr = m_agg_request.add_efr();
    efr->mutable_buff()->CopyFrom(*current_buff.get());
    efr->mutable_frame_info()->mutable_flow()->set_id(flow_id);
    for (auto stage_id : m_stage.next_stage()) {
        efr->mutable_frame_info()->mutable_flow()->add_stage_id(stage_id);
    }
    efr->mutable_frame_info()->mutable_frame()->set_frame_num(m_frame_num++);
    efr->mutable_frame_info()->mutable_frame()->set_client_context(client_context);
    efr->mutable_frame_info()->mutable_frame()->set_is_scaled((m_dec->params.frameWidth != 0) || (m_dec->params.frameHeight != 0));
    efr->mutable_frame_info()->mutable_frame()->set_width(width);
    efr->mutable_frame_info()->mutable_frame()->set_height(height);
    efr->mutable_frame_info()->mutable_frame()->set_format(m_dec->params.output_format);

    auto free_msg_buf_size = broker_thread::get_free_send_buffer_size(m_broker_socket);
    if (free_msg_buf_size < MSG_MIN_BUFF_SIZE) {
        LOG(WARNING) << "Dropping frame! - free_msg_buf_size < " << int(MSG_MIN_BUFF_SIZE);
        m_dec->stats.dropped_frames++;
        return;
    }
    if (m_agg_request.efr_size() >= m_batch_size) {
        LOG(DEBUG) << "Sending event DECODED_FRAME_READY with " << m_agg_request.efr_size() << " frames";
        if (!broker_thread::send_msg(m_broker_socket, messages::enums::DECODED_FRAME_READY, m_agg_request)) {
            LOG(ERROR) << "Failed sending msg DECODED_FRAME_READY";
            return;
        }
        m_agg_request.Clear();
    }
}
