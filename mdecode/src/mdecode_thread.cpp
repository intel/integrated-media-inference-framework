
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
#include "common_os_utils.h"
#include "common_string_utils.h"

#include <messages/proto/enums.pb.h>
#include <messages/proto/mdecode.pb.h>
#include <messages/proto/mgmt.pb.h>

#include <functional>

// #define DEBUG_DUMP_DECODER_INPUT
#define BS_MOVE_SIZE (BS_INIT_SIZE - 2 * 1024 * 1024)
#define NUM_OF_COLORS (4)

using namespace imif;
using namespace common;
using namespace mdecode;

MDecodeThread::MDecodeThread(const std::string broker_uds, imif::common::logging *pLogger)
    : broker_thread("MDECODE_THREAD", broker_uds), m_module_name("mdecode"), m_broker_uds_path(broker_uds), m_pLogger(pLogger)
{
    m_work_last_report_timestamp = std::chrono::steady_clock::now();
    m_next_register = std::chrono::steady_clock::now();
    set_select_timeout(SELECT_TIMEOUT_MSEC);
    m_dump_path.clear();
    m_pool_input_map.clear();
    m_image_threads.clear();
    m_flow_stage.clear();
    m_pool_output_map.clear();
    m_configs.clear();
    m_flows.clear();
    m_stream_decoder_vec.clear();
}

MDecodeThread::~MDecodeThread()
{
    LOG(TRACE) << "destructor()";
    reset();
}

void MDecodeThread::reset()
{
    LOG(INFO) << "reset()";

    log_stats(true, true, false);
    for (auto dec_it : m_stream_decoder_vec) {
        uint32_t flow = dec_it.first;
        remove_flow(flow, true);
    }
    m_stream_decoder_vec.clear();

    m_pool_input_map.clear();
    m_pool_output_map.clear();

    m_flows.clear();
    m_configs.clear();

    common::shmem_buff_factory::shmem_pool_map.clear();
    m_enabled = false;
}

void MDecodeThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    should_stop = true;
    reset();
}

bool MDecodeThread::post_init()
{
    // Register to bus messages

    subscribe({messages::enums::Opcode::MGMT_ADD_FLOW, messages::enums::Opcode::MGMT_REMOVE_FLOW,
               messages::enums::Opcode::MGMT_ADD_CONFIG, messages::enums::Opcode::MGMT_REMOVE_CONFIG,
               messages::enums::Opcode::MGMT_GLOBAL_CONFIG, messages::enums::Opcode::MGMT_REGISTER_RESPONSE,
               messages::enums::Opcode::MGMT_ENABLE, messages::enums::Opcode::MGMT_SET_LOG_LEVEL,
               messages::enums::Opcode::MGMT_RESET});

    return true;
}

bool MDecodeThread::handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
{
    switch (opcode) {
    case messages::enums::Opcode::MGMT_REGISTER_RESPONSE: {
        messages::mgmt::RegisterResponse response;
        if (!response.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing MgmtRegisterResponse";
            return false;
        }
        if (!common::string_utils::caseless_eq(response.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(DEBUG) << "Recieved MGMT_REGISTER_RESPONSE";
        m_module_id = response.module_id();
        m_registered = true;

    } break;
    case messages::enums::Opcode::MGMT_ENABLE: {
        messages::mgmt::Enable request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing MgmtEnable message";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(DEBUG) << "Recieved MGMT_ENABLE";
        m_enabled = request.enable();

        if (m_enabled) {
            handle_enable();
        } else {
            handle_disable();
        }
    } break;
    case messages::enums::Opcode::MGMT_SET_LOG_LEVEL: {
        messages::mgmt::SetLogLevel request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing SetLogLevel request";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        m_pLogger->set_log_level_state(eLogLevel(request.log_level()), request.new_state());
    } break;
    case messages::enums::Opcode::MGMT_RESET: {
        messages::mgmt::ResetMod request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing reset request";
            return false;
        }
        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name) &&
            !common::string_utils::caseless_eq(request.module_name(), "all")) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "Received MGMT_RESET";
        reset();

    } break;
    case messages::enums::Opcode::MGMT_ADD_FLOW: {
        messages::mgmt::AddFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing Flow";
            return false;
        }

        LOG(INFO) << "MGMT_ADD_FLOW: " << request;

        if (!add_flow(request.flow())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_FLOW: {
        messages::mgmt::RemoveFlow request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveFlow";
            return false;
        }
        LOG(INFO) << "MGMT_REMOVE_FLOW: " << request;

        if (!remove_flow(request.flow_id())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_GLOBAL_CONFIG: {
        messages::mgmt::GlobalConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing GlobalConfig";
            return false;
        }

        LOG(INFO) << "MGMT_GLOBAL_CONFIG: " << request;

        if (!global_config(request)) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_ADD_CONFIG: {
        messages::mgmt::AddConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing AddConfig";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "MGMT_ADD_CONFIG: " << request;

        if (!add_config(request.config())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;
    case messages::enums::Opcode::MGMT_REMOVE_CONFIG: {
        messages::mgmt::RemoveConfig request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing RemoveConfig";
            return false;
        }

        if (!common::string_utils::caseless_eq(request.module_name(), m_module_name)) {
            // ignore configs that wasnt sent to me
            break;
        }

        LOG(INFO) << "MGMT_REMOVE_CONFIG: " << request;

        if (!remove_config(request.config_id())) {
            // Send error to MGMT
            // send_msg(messages::enums::MGMT_EVENT_ERROR, request.req_id);
        }
    } break;

    // grecefully ignore msgs
    case messages::enums::Opcode::INPUT_BS_READY: {
        messages::mstream::EventBsReady request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing EventBsReady message";
            return false;
        }

        LOG(INFO) << "INPUT_BS_READY: " << request;
        return decode_flow(request);

    } break;
    case messages::enums::Opcode::INPUT_JPEG_READY: {
        messages::types::EventFrameReady request;
        if (!request.ParseFromArray(msg, msg_len)) {
            LOG(ERROR) << "Failed parsing EventFrameReady message";
            return false;
        }
        for (auto &frame_ready : request.efr()) {
            // LOG(INFO) << "MSTREAM_FRAME_READY: " << frame_ready;
            auto frame_info = frame_ready.frame_info();
            auto flow = frame_info.flow();
            auto flow_id = flow.id();
            auto it = m_image_threads.find(flow_id);
            if (it == m_image_threads.end()) {
                return true;
            }

            it->second->push_event(frame_ready);
        }
    } break;
    default: {
        LOG(ERROR) << "Unknown opcode " << std::hex << int(opcode) << std::dec;
    } break;
    }

    return true;
}

bool MDecodeThread::handle_msg(std::shared_ptr<Socket> sd) { return true; }

void MDecodeThread::forceCloseSocket(std::shared_ptr<Socket> sd)
{
    LOG(INFO) << "Force socket close!";
    sd->closeSocket();
    del_socket(sd);
    sd.reset();
}

int MDecodeThread::runDecoder(std::shared_ptr<sStreamDecInst> pDec)
{
    mfxStatus sts = MFX_ERR_NONE;

    if (pDec == nullptr) {
        LOG(ERROR) << "pDec is null!";
        return STS_READ_FATAL;
    }

    if (!pDec->pipeline->IsInitialized()) {
        LOG(DEBUG) << "Call BsInit()";
        sts = pDec->pipeline->BsInit(&pDec->params);
        if (MFX_ERR_MORE_DATA == sts) {
            LOG(DEBUG) << "...Need more data, dec->pipline.BsInit() --> MFX_ERR_MORE_DATA";
            return STS_DEC_MORE_DATA;
        } else if (MFX_ERR_NONE != sts) {
            LOG(ERROR) << "BsInit() failed --> sts=" << StatusToString(sts);
            return STS_DEC_FATAL;
        }
    }

    auto pBSout = pDec->pipeline->GetBS();

    if (pBSout->DataLength == 0) {
        LOG(ERROR) << "Need not happen, pBSout->DataLength == 0";
        return STS_DEC_FATAL;
    }

    int ret_sts = STS_DEC_NO_ERROR;
    auto dec_in_data_length = pBSout->DataLength;
    // LOG(DEBUG) << "==> RunDecoder()";
    // LOG(DEBUG) << "Pre RunDecoder() BS: DataLength=" << pBSout->DataLength << " DataOffset=" << pBSout->DataOffset;
    sts = pDec->pipeline->RunDecoder();
    // LOG(DEBUG) << "Post RunDecoder() BS: DataLength=" << pBSout->DataLength << " DataOffset=" << pBSout->DataOffset;
    pDec->pipeline->busyFlag(false);
    if (MFX_ERR_MORE_DATA == sts) {
        ret_sts = STS_DEC_MORE_DATA;
    } else if (MFX_ERR_MORE_SURFACE == sts) {
        ret_sts = STS_DEC_MORE_DATA;
    } else if (MFX_WRN_DEVICE_BUSY == sts) {
        LOG(DEBUG) << "RunDecoding(): MFX_WRN_DEVICE_BUSY";
        pDec->pipeline->busyFlag(true);
        if (pDec->low_latency && pBSout->DataLength != 0) {
            ret_sts = STS_DEC_BUSY;
        }
    } else if (MFX_WRN_IN_EXECUTION == sts) {
        LOG(DEBUG) << "RunDecoding(): MFX_WRN_IN_EXECUTION";
        pDec->pipeline->busyFlag(true);
        if (pDec->low_latency && pBSout->DataLength != 0) {
            ret_sts = STS_DEC_BUSY;
        }
    } else if (MFX_ERR_NONE != sts) {
        LOG(ERROR) << "RunDecoding(): ERROR sts= " << StatusToString(sts);
        return STS_DEC_FATAL;
    }
    auto dec_data_consumed = dec_in_data_length - pBSout->DataLength;
    pDec->stats.bytes_in += dec_data_consumed;
    // LOG(DEBUG) << "==> RunDecoder() dec_data_consumed=" << dec_data_consumed;
    if (dec_data_consumed) {
        ret_sts |= STS_DEC_MORE_DATA;
    }

    if (pDec->low_latency && pBSout->DataLength) {
        ret_sts |= STS_DEC_DIDNT_CONSUME;
    }

#ifdef DEBUG_DUMP_DECODER_INPUT
    if (dec_data_consumed) {
        if (pDec->params.flow.flow_id() == 0) {
            auto dec_in_data_ofset = pBSout->DataOffset;
            auto pBS = pBSout;
            LOG(INFO) << "DUMP: DataLength=" << dec_data_consumed << " DataOffset=" << dec_in_data_ofset;
            std::string fname = m_pipe_config[pDec->params.flow.pipe_id()].dump_path() + "bs_flow_id" +
                                std::to_string(int(pDec->params.flow.flow_id())) + ".h264";
            auto wr_len = imif::common::string_utils::dump_bin2file(fname, pBS->Data + dec_in_data_ofset, dec_data_consumed);
            if (wr_len != dec_data_consumed) {
                LOG(ERROR) << "wr_len != data_len !";
                ret_sts |= STS_DEC_FATAL;
            }
        }
    }
#endif

    return ret_sts;
}

bool WriteNextFrame(mfxFrameSurface1 *pSurface, uint8_t *destPtr)
{
    if (!pSurface) {
        LOG(ERROR) << "pSurface == nullptr";
        return false;
    }
    if (!destPtr) {
        LOG(ERROR) << "destPtr == nullptr";
        return false;
    }

    mfxFrameInfo &pInfo = pSurface->Info;
    mfxFrameData &pData = pSurface->Data;

    uint32_t i, h, w;
    size_t offset = 0;

    switch (pInfo.FourCC) {
    case MFX_FOURCC_NV12: {
        for (i = 0; i < pInfo.CropH; i++) {
            uint8_t *p = pData.Y + (pInfo.CropY * pData.Pitch + pInfo.CropX) + i * pData.Pitch;
            std::copy_n(p, 1 * pInfo.CropW, destPtr + offset);
            offset += 1 * pInfo.CropW;
        }

        for (i = 0; i < (mfxU32)pInfo.CropH / 2; i++) {
            uint8_t *p = pData.UV + (pInfo.CropY * pData.Pitch + pInfo.CropX) + i * pData.Pitch;
            std::copy_n(p, 1 * pInfo.CropW, destPtr + offset);
            offset += 1 * pInfo.CropW;
        }
        break;
    } break;
    case MFX_FOURCC_RGB4: {
        uint8_t *ptr;

        if (pInfo.CropH > 0 && pInfo.CropW > 0) {
            w = pInfo.CropW;
            h = pInfo.CropH;
        } else {
            w = pInfo.Width;
            h = pInfo.Height;
        }

        ptr = std::min(std::min(pData.R, pData.G), pData.B);
        ptr = ptr + pInfo.CropX + pInfo.CropY * pData.Pitch;

        for (i = 0; i < h; i++) {
            size_t copy_size = 4 * w;
            std::copy_n(ptr + i * pData.Pitch, copy_size, destPtr + offset);
            offset += copy_size;
        }
    } break;

    default:
        LOG(ERROR) << "Unknown type! " << int(pInfo.FourCC);
        return false;
    }

    return true;
}

bool WriteNextFrameI420(mfxFrameSurface1 *pSurface, uint8_t *destPtr)
{
    if (!pSurface) {
        LOG(ERROR) << "pSurface == nullptr";
        return false;
    }
    if (!destPtr) {
        LOG(ERROR) << "destPtr == nullptr";
        return false;
    }

    mfxFrameInfo &pInfo = pSurface->Info;
    mfxFrameData &pData = pSurface->Data;

    uint32_t i, j, h, w;
    size_t offset = 0;

    // Write Y
    for (i = 0; i < pInfo.CropH; i++) {
        uint8_t *p = pData.Y + (pInfo.CropY * pData.Pitch + pInfo.CropX) + i * pData.Pitch;
        size_t copy_size = pInfo.CropW;
        std::copy_n(p, copy_size, destPtr + offset);
        offset += copy_size;
    }

    // Write U and V
    h = pInfo.CropH / 2;
    w = pInfo.CropW;
    for (i = 0; i < h; i++) {
        for (j = 0; j < w; j += 2) {
            uint8_t *p = pData.UV + (pInfo.CropY * pData.Pitch / 2 + pInfo.CropX) + i * pData.Pitch + j;
            size_t copy_size = 1;
            std::copy_n(p, copy_size, destPtr + offset);
            offset += copy_size;
        }
    }
    for (i = 0; i < h; i++) {
        for (j = 1; j < w; j += 2) {
            uint8_t *p = pData.UV + (pInfo.CropY * pData.Pitch / 2 + pInfo.CropX) + i * pData.Pitch + j;
            size_t copy_size = 1;
            std::copy_n(p, copy_size, destPtr + offset);
            offset += copy_size;
        }
    }

    return true;
}

void MDecodeThread::deliver_frame(mfxFrameSurface1 *frame, uint32_t flow_id, uint64_t client_context)
{
    auto elem = m_stream_decoder_vec.find(flow_id);
    if (elem == m_stream_decoder_vec.end()) {
        LOG(ERROR) << "Can't find decoder for flow_id=" << flow_id;
        return;
    }

    auto dec = elem->second;
    if (dec == nullptr) {
        LOG(ERROR) << "Can't find decoder for flow_id=" << flow_id;
        return;
    }

    dec->stats.first_frame_timestamp = std::chrono::steady_clock::now();
    dec->stats.frames++;

    uint64_t frame_num = dec->stats.total_frames + dec->stats.frames;

    LOG(DEBUG) << "==> Deliver frame " << frame_num << " flow=" << flow_id;
    if (dec->frame_writer) {
        mfxStatus sts =
            dec->params.outI420 ? dec->frame_writer->WriteNextFrameI420(frame) : dec->frame_writer->WriteNextFrame(frame);
        if (MFX_ERR_NONE != sts) {
            LOG(ERROR) << "Failed to write frame for flow=" << flow_id;
        }
    }

    auto pool_it = m_pool_output_map.find(flow_id);
    if (pool_it == m_pool_output_map.end()) {
        LOG(FATAL) << "Unknown flow=" << flow_id;
        return;
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

    size_t frameBytes = dec->pipeline->getFrameBytes();

    auto &aggregated_request = m_agg_request;

    if (pool_it->second->get_consecutive_free() < frameBytes) {
        LOG(WARNING) << "Dropping frame! - There is not enough shmem space to allocate buff for flow_id " << flow_id;
        dec->stats.dropped_frames++;
        if (aggregated_request.efr_size() > 0) {
            LOG(DEBUG) << "Sending event DECODED_FRAME_READY with " << aggregated_request.efr_size() << " frames";
            if (!send_msg(messages::enums::DECODED_FRAME_READY, aggregated_request)) {
                LOG(ERROR) << "Failed sending msg DECODED_FRAME_READY";
                return;
            }
            aggregated_request.Clear();
        }
        return;
    }
    // allocate new buff
    auto current_buff = pool_it->second->alloc_buff(frameBytes);
    if (!current_buff) {
        LOG(ERROR) << "Failed allocating new buff";
        dec->stats.dropped_frames++;
        return;
    }

    uint8_t *ptr = (uint8_t *)current_buff->ptr();

    bool sts = dec->params.outI420 ? WriteNextFrameI420(frame, ptr) : WriteNextFrame(frame, ptr);
    if (!sts) {
        LOG(ERROR) << "Failed copying frame";
        current_buff->drop();
        return;
    }

    auto stage = m_flow_stage[flow_id];

    if (stage.next_stage_size() == 0) {
        return;
    }

    auto efr = aggregated_request.add_efr();
    efr->mutable_buff()->CopyFrom(*current_buff.get());
    efr->mutable_frame_info()->mutable_flow()->set_id(flow_id);
    for (auto stage_id : stage.next_stage()) {
        efr->mutable_frame_info()->mutable_flow()->add_stage_id(stage_id);
    }
    efr->mutable_frame_info()->mutable_frame()->set_frame_num(frame_num);
    efr->mutable_frame_info()->mutable_frame()->set_client_context(client_context);
    efr->mutable_frame_info()->mutable_frame()->set_is_scaled((dec->params.frameWidth != 0) || (dec->params.frameHeight != 0));
    efr->mutable_frame_info()->mutable_frame()->set_width(width);
    efr->mutable_frame_info()->mutable_frame()->set_height(height);
    efr->mutable_frame_info()->mutable_frame()->set_format(dec->params.output_format);
    efr->mutable_frame_info()->set_timestamp(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    if (aggregated_request.efr_size() >= m_batch_size) {
        auto free_msg_buf_size = get_free_send_buffer_size();
        if (free_msg_buf_size < MSG_MIN_BUFF_SIZE) {
            LOG(WARNING) << "Not enough space to send msg! - dropping frames!";
            current_buff->drop();
            current_buff = nullptr;
            aggregated_request.mutable_efr()->RemoveLast();

            dec->stats.dropped_frames++;
            return;
        }
        LOG(DEBUG) << "Sending event DECODED_FRAME_READY with " << aggregated_request.efr_size() << " frames";
        if (!send_msg(messages::enums::DECODED_FRAME_READY, aggregated_request)) {
            LOG(ERROR) << "Failed sending msg DECODED_FRAME_READY";
            return;
        }
        aggregated_request.Clear();
    }
}

bool MDecodeThread::socket_disconnected(std::shared_ptr<Socket> sd)
{
    if (sd->getUdsPath().empty()) {
        LOG(INFO) << "TCP socket disconnected !!!";
    } else {
        LOG(INFO) << "UDS socket disconnected !!!";
    }
    return true;
}

bool MDecodeThread::before_select()
{

    if (!m_registered) {
        auto now = std::chrono::steady_clock::now();
        if (now > m_next_register) {
            // Register to management
            messages::mgmt::RegisterRequest mgmt_register;
            mgmt_register.set_module_name(m_module_name);
            send_msg(messages::enums::MGMT_REGISTER_REQUEST, mgmt_register);
            LOG(DEBUG) << "Sent register request";

            m_next_register = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        }
    }
    if (!m_enabled) {
        return true;
    }

    log_stats();

    for (auto elem : m_stream_decoder_vec) {
        if (!decode_flow(elem.first)) {
            LOG(ERROR) << "Failed to decode flow=" << elem.first;
        }
    }

    return true;
}

bool MDecodeThread::after_select(bool timeout)
{
    for (auto &elem : m_stream_decoder_vec) {
        auto pDec = elem.second;
        if (!pDec->low_latency) {
            if (pDec->pipeline->busyFlag() && runDecoder(pDec) & STS_DEC_FATAL) {
                return false;
            }
        }
    }

    return true;
}

void MDecodeThread::log_stats(bool force, bool full_report, bool periodic)
{
    auto last_report_time_msec =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_work_last_report_timestamp)
            .count();

    if (last_report_time_msec < WORK_REPORT_INTRVAL_MSEC && !force) {
        return;
    }

    std::stringstream statistics_stream;

    statistics_stream << "Decoder statistics:";
    uint64_t total_frames = 0;
    uint64_t total_dropped_frames = 0;
    double total_mbps = 0;
    double total_rec_mbps = 0;
    double total_fps = 0;
    double total_dropped_fps = 0;

    for (auto dec_it : m_stream_decoder_vec) {
        auto flow_id = dec_it.first;
        auto dec = dec_it.second;
        uint64_t decode_time_msec;
        if (periodic) {
            decode_time_msec = last_report_time_msec;
        } else {
            decode_time_msec = std::chrono::duration_cast<std::chrono::milliseconds>(dec->stats.last_frame_timestamp -
                                                                                     dec->stats.first_frame_timestamp)
                                   .count();
        }

        double decode_time_sec = double(decode_time_msec) / 1000.0;

        dec->stats.total_bytes_recieved += dec->stats.bytes_recieved;
        dec->stats.total_bytes_in += dec->stats.bytes_in;
        dec->stats.total_frames += dec->stats.frames;
        dec->stats.total_dropped_frames += dec->stats.dropped_frames;

        uint64_t frames;
        uint64_t dropped_frames;
        double rec_mbps;
        double mbps;

        if (periodic) {
            frames = dec->stats.frames;
            dropped_frames = dec->stats.dropped_frames;
            rec_mbps = 8.0 * (double(dec->stats.bytes_recieved) / decode_time_sec) / 1024 / 1024;
            mbps = 8.0 * (double(dec->stats.bytes_in) / decode_time_sec) / 1024 / 1024;
        } else {
            frames = dec->stats.total_frames;
            dropped_frames = dec->stats.total_dropped_frames;
            rec_mbps = 8.0 * (double(dec->stats.total_bytes_recieved) / decode_time_sec) / 1024 / 1024;
            mbps = 8.0 * (double(dec->stats.total_bytes_in) / decode_time_sec) / 1024 / 1024;
        }

        dec->stats.bytes_recieved = 0;
        dec->stats.bytes_in = 0;
        dec->stats.frames = 0;
        dec->stats.dropped_frames = 0;

        double fps = double(frames) / decode_time_sec;
        double dropped_fps = double(dropped_frames) / decode_time_sec;

        total_mbps += mbps;
        total_fps += fps;
        total_dropped_fps += dropped_fps;
        total_frames += frames;
        total_dropped_frames += dropped_frames;
        total_rec_mbps += rec_mbps;
        if (full_report) {
            statistics_stream << "  Flow id: " << flow_id;
            statistics_stream << "    decode time sec: " << decode_time_sec;
            statistics_stream << "    output frames: " << frames;
            statistics_stream << "    dropped frames: " << dropped_frames;
            statistics_stream << "    recieve mbps: " << rec_mbps;
            statistics_stream << "    input mbps: " << mbps;
            statistics_stream << "    output fps: " << fps;
            statistics_stream << "    dropped fps: " << dropped_fps << std::endl;
        }
    }
    auto streams = m_stream_decoder_vec.size();
    statistics_stream << "  Total:";
    statistics_stream << "    streams:" << streams;
    statistics_stream << "    output frames:" << total_frames;
    statistics_stream << "    dropped frames: " << total_dropped_frames;
    statistics_stream << "    recieve mbps: " << total_rec_mbps;
    statistics_stream << "    input mbps: " << total_mbps;
    statistics_stream << "    output fps: " << total_fps;
    statistics_stream << "    dropped fps: " << total_dropped_fps;

    LOG(INFO) << statistics_stream.str();
    messages::mgmt::Statistics statistic;
    statistic.set_topic(m_module_name);
    statistic.set_stat(statistics_stream.str());
    send_msg(messages::enums::MGMT_EVENT_STAT_READY, statistic);

    m_work_last_report_timestamp = std::chrono::steady_clock::now();
}

bool MDecodeThread::add_config(const messages::types::Config &config)
{
    uint32_t config_id = config.id();
    if (m_configs.find(config_id) != m_configs.end()) {
        LOG(ERROR) << "Config id " << config_id << " already exist!";
        return false;
    }

    messages::mdecode::Config gvdConfig;
    if (!config.config().UnpackTo(&gvdConfig)) {
        LOG(ERROR) << "Failed getting config";
        return false;
    }

    std::string format = gvdConfig.output_format();
    if (format.empty() || !((format == "nv12") || (format == "i420") || (format == "rgb4") || (format == "jpeg"))) {
        LOG(ERROR) << "output format '" << format << "' not supported!, valid options: nv12,i420,rgb4,jpeg";
        return false;
    }

    if (gvdConfig.threads_num() < 2) {
        LOG(ERROR) << "Config invalid: number of threads must be 2 or more";
        return false;
    }

    m_configs[config_id] = gvdConfig;

    return true;
}

bool MDecodeThread::remove_config(uint32_t config_id)
{
    if (m_configs.find(config_id) == m_configs.end()) {
        LOG(ERROR) << "Can't remove config " << config_id << ". Doesn't exist!";
        return false;
    }

    const auto &flow_it = std::find_if(m_flow_stage.begin(), m_flow_stage.end(),
                                       [config_id](const std::pair<uint32_t, messages::types::Stage> &stage_it) {
                                           return stage_it.second.config_id() == config_id;
                                       });
    if (flow_it != m_flow_stage.end()) {
        LOG(ERROR) << "Cant remove config_id:" << config_id << " as it's used by flow:" << flow_it->first;
        return false;
    }

    m_configs.erase(config_id);
    return true;
}

bool MDecodeThread::add_flow(const messages::types::Flow &flow)
{
    uint32_t flow_id = flow.id();
    if (m_flows.find(flow_id) != m_flows.end()) {
        LOG(ERROR) << "Can't add flow " << flow_id << "- already exist!";
        return false;
    }

    // Make sure that mdecode isn't responsible for more then 1 stage
    uint32_t stages =
        std::count_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });
    if (stages > 1) {
        LOG(ERROR) << "Invalid flow configuration - mdecode participate more then once";
        return false;
    } else if (stages == 0) {
        LOG(DEBUG) << "mdecode does not participate in this flow " << flow_id;
        return true;
    }

    auto stage_it =
        std::find_if(flow.pipeline().stage().begin(), flow.pipeline().stage().end(), [this](const messages::types::Stage &stage) {
            return common::string_utils::caseless_eq(stage.module_name(), m_module_name);
        });

    auto &stage = *stage_it;
    if (stage.config_case() != stage.kConfigId) {
        LOG(ERROR) << "config id isn't set!!!";
        return false;
    }

    uint32_t config_id = stage.config_id();
    uint32_t source_id = flow.source_id();

    if (m_stream_decoder_vec.find(flow_id) != m_stream_decoder_vec.end()) {
        LOG(DEBUG) << "Decoder instance for flow_id " << flow_id << " already exist";
        return false;
    }

    auto config_it = m_configs.find(config_id);
    if (config_it == m_configs.end()) {
        LOG(ERROR) << "Config id " << config_id << " doesn't exist!";
        return false;
    }

    auto config = config_it->second;

    size_t frame_size = (config.inline_scale_width() * config.inline_scale_height());
    if (frame_size == 0) {
        LOG(WARNING) << "output scale width / height is zero, allocating 1080p frames.";
        frame_size = 1920 * 1080;
    }
    if (config.output_format() == "nv12") {
        frame_size = frame_size + (frame_size >> 1);
    } else if (config.output_format() == "i420") {
        frame_size = frame_size + (2 * (frame_size >> 2));
    } else if (config.output_format() == "rgb4") {
        frame_size = frame_size * 4;
    }

    if ((config.video_type() == "jpg") || (config.video_type() == "jpeg") || (config.video_type() == "mjpeg")) {
        LOG(DEBUG) << "got an image, spawning mdecode_image_thread";

        if (m_image_threads.find(flow_id) != m_image_threads.end()) {
            LOG(ERROR) << "Aborting: thread already exists for flow_id: " << flow_id;
            return false;
        }

        frame_size = DEFAULT_IMAGE_SIZE;
    }

    size_t memory_size = MDECODE_DECODED_FRAME_COUNT * frame_size;

    int pid = common::os_utils::get_pid();
    int shmkey = (pid << 8) | flow_id;
    auto pool = std::make_shared<imif::common::shmem_pool>(shmkey, memory_size);
    if (!pool) {
        LOG(FATAL) << "MDecodeThread: Failed allocating pool!";
        should_stop = true;
        return false;
    }
    if (!pool->attach()) {
        LOG(FATAL) << "MDecodeThread: Failed attaching to shmem";
        should_stop = true;
        return false;
    }

    auto dec = std::make_shared<sStreamDecInst>();
    if (!dec) {
        LOG(FATAL) << "Failed allocating decoder";
        return false;
    }

    dec->params.flow_id = flow_id;
    if (!setDecoderParams(dec->params, config)) {
        LOG(ERROR) << "setDecoderParams() failed!";
        return false;
    }

    if ((config.video_type() == "jpg") || (config.video_type() == "jpeg") || (config.video_type() == "mjpeg")) {
        auto image_thread = std::make_shared<mdecode_image_thread>(m_broker_uds_path, stage, pool, dec->params);
        if (!image_thread) {
            LOG(FATAL) << "Aborting: failed to construct thread";
            return false;
        }
        if (!image_thread->start()) {
            LOG(FATAL) << "Aborting: failed to start thread";
            return false;
        }
        m_image_threads[flow_id] = image_thread;
        subscribe(messages::enums::Opcode::INPUT_JPEG_READY);
        return true;
    }

    dec->pipeline = make_unique<CStreamDecodingPipeline>();
    if (!dec->pipeline) {
        LOG(FATAL) << "Failed allocating pipline";
        return false;
    }

    auto sts = dec->pipeline->InitialInit(&dec->params);
    if (sts != MFX_ERR_NONE) {
        LOG(ERROR) << "pipeline.InitialInit() failed --> " << StatusToString(sts);
        return false;
    }

    dec->pipeline->SetDeliverDecodedFrameCLBK(
        std::bind(&MDecodeThread::deliver_frame, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

    if (config.complete_frame()) {
        dec->low_latency = true;
    }

    if (!m_dump_path.empty()) {
        dec->frame_writer = make_unique<CSmplYUVWriter>();
        sts = dec->frame_writer->Init(dec->params.strDstFile, 1);
    }

    dec->pipeline->setFrameBytes(frame_size);

    subscribe(messages::enums::Opcode::INPUT_BS_READY);
    m_pool_output_map[flow_id] = pool;
    m_stream_decoder_vec[flow_id] = dec;
    sSourceConfig source_config;
    source_config.source_id = source_id;
    source_config.config_id = config_id;
    source_config.stage_id = stage.id();
    m_flows[flow_id] = source_config;
    m_flow_stage[flow_id] = stage;

    return true;
}

bool MDecodeThread::remove_flow(uint32_t flow_id, bool skip_erase)
{
    auto image_thread_it = m_image_threads.find(flow_id);
    if (image_thread_it != m_image_threads.end()) {
        image_thread_it->second->stop();
    }
    auto flow_it = m_flows.find(flow_id);
    if (flow_it == m_flows.end()) {
        LOG(ERROR) << "Unknown flow_id " << flow_id;
        return false;
    }
    auto dec_it = m_stream_decoder_vec.find(flow_id);
    if (dec_it == m_stream_decoder_vec.end()) {
        LOG(ERROR) << "Can't remove flow=" << int(flow_id);
        return false;
    }

    auto dec = dec_it->second;
    if (!dec) {
        LOG(ERROR) << "Can't remove flow=" << int(flow_id);
        return false;
    }
    if (dec->pipeline) {
        dec->pipeline->Close();
        dec->pipeline = nullptr;
    }
    if (dec->frame_writer) {
        dec->frame_writer->Close();
        dec->frame_writer = nullptr;
    }
    dec = nullptr;
    if (!skip_erase)
        m_stream_decoder_vec.erase(flow_id);

    m_pool_output_map.erase(flow_id);

    auto pool = m_pool_input_map[flow_id];
    m_pool_input_map.erase(flow_id);
    if (pool) {
        if (pool.use_count() == 2) { // Me and shmem factory
            imif::common::shmem_buff_factory::free_shmem_pool(pool->shmkey());
        }
    }

    return true;
}

bool MDecodeThread::setDecoderParams(sStreamInputParams &params, messages::mdecode::Config config)
{
    //MediaSDK version	1.27
    // set output configuration
    params.useHWLib = true;
    params.videoAccelerationLib = MFX_LIBVA_DRM;

    params.frameWidth = (mfxU16)config.inline_scale_width();
    params.frameHeight = (mfxU16)config.inline_scale_height();

    if (config.video_type() == "h264") {
        params.videoType = MFX_CODEC_AVC;
        LOG(INFO) << "videoType=MFX_CODEC_AVC";
    } else if (config.video_type() == "h265") {
        params.videoType = MFX_CODEC_HEVC;
        LOG(INFO) << "videoType=MFX_CODEC_HEVC";
    } else if (config.video_type() == "jpeg") {
        params.videoType = MFX_CODEC_JPEG;
        params.useLowLatencyMode = true;
        LOG(INFO) << "videoType=MFX_CODEC_JPEG";
    } else {
        LOG(ERROR) << "config.video_type() not supported! --> " << config.video_type();
        return false;
    }

    if (config.output_format() == "nv12") {
        params.videoFourcc = MFX_FOURCC_NV12;
        msdk_opt_read("nv12", params.output_format);
    } else if (config.output_format() == "i420") {
        params.videoFourcc = MFX_FOURCC_NV12;
        params.outI420 = true;
        msdk_opt_read("i420", params.output_format);
    } else if (config.output_format() == "rgb4") {
        params.videoFourcc = MFX_FOURCC_RGB4;
        msdk_opt_read("bgra", params.output_format);
    } else {
        LOG(ERROR) << "supported config.format --> " << config.output_format();
        return false;
    }

    if (params.videoType != MFX_CODEC_JPEG) {
        params.useLowLatencyMode = config.complete_frame();
    }

    params.decThreadNum = config.threads_num();

    messages::mdecode::OptionalConfig optional_config;
    if (config.optional_config().UnpackTo(&optional_config)) {
        params.decPostProcessing = (mfxU16)optional_config.gen_postproc();
        params.decPipelineAsyncronousDepth = (mfxU16)optional_config.async_depth();
    }
    m_batch_size = optional_config.batch_size();

    if (params.decPipelineAsyncronousDepth == 0 || params.decPipelineAsyncronousDepth > 20) {
        LOG(INFO) << "forcing  decPipelineAsyncronousDepth = 4";
        params.decPipelineAsyncronousDepth = 4;
    }

    params.errorReport = m_global_config.error_report();

    // set output file
    if (!m_dump_path.empty()) {
        std::string output_fname;
        output_fname =
            m_dump_path + std::string("flow_") + std::to_string(params.flow_id) + "." + std::string(params.output_format);
        msdk_opt_read(output_fname.c_str(), params.strDstFile);
    }

    return true;
}

size_t MDecodeThread::copyBsData(std::shared_ptr<sStreamDecInst> pDec, uint8_t *data, size_t payload_len)
{
    auto pBS = pDec->pipeline->GetBS();

    if (pBS->DataLength == 0) {
        pBS->DataOffset = 0;
    }

    size_t avilable_buffer_len = (pBS->MaxLength - pBS->DataOffset) - pBS->DataLength;

    if (payload_len > avilable_buffer_len) {
        if ((pBS->DataLength > 0) && (pBS->DataOffset > BS_MOVE_SIZE)) {
            LOG(DEBUG) << " memmove pBSin, DataLength=" << int(pBS->DataLength) << " DataOffset=" << int(pBS->DataOffset);
            memmove(pBS->Data, pBS->Data + pBS->DataOffset, pBS->DataLength);
            pBS->DataOffset = 0;
            avilable_buffer_len = (pBS->MaxLength - pBS->DataOffset) - pBS->DataLength;
            LOG(DEBUG) << " Post memmove: pBSin DataLength=" << int(pBS->DataLength) << " DataOffset=" << int(pBS->DataOffset)
                       << " MaxLength =" << int(pBS->MaxLength);
        }
    }

    size_t copy_size = std::min(avilable_buffer_len, payload_len);
    std::copy_n(data, copy_size, (pBS->Data + pBS->DataOffset + pBS->DataLength));

    pBS->DataLength += copy_size;

    return copy_size;
}

bool MDecodeThread::decode_flow(messages::mstream::EventBsReady &decode)
{
    bool has_valid_flow = false;
    // for efficiency in the ordinary valid flow case, consider we moving this check.
    for (auto &flow : decode.flow()) {
        auto flow_it = m_flows.find(flow.id());
        if (flow_it != m_flows.end()) {
            has_valid_flow = true;
            break;
        }
    }
    if (!has_valid_flow) {
        LOG(DEBUG) << "No known flows...";
        return true;
    }

    auto buff = decode.buff();

    auto pool = common::shmem_buff_factory::get_shmem_pool(buff.shmkey(), buff.shmsize());
    if (!pool) {
        LOG(ERROR) << "Can't get shm_pool for key=" << int(buff.shmkey());
        return false;
    }

    auto buff_p = std::make_shared<shmem_buff>(pool, buff);
    if (!buff_p) {
        LOG(ERROR) << "Failed getting shmem buff";
        return false;
    }

    if (!m_enabled) {
        return true;
    }

    for (auto &flow : decode.flow()) {
        if (m_flows.find(flow.id()) == m_flows.end()) {
            continue;
        }

        if (m_pool_input_map.find(flow.id()) == m_pool_input_map.end()) {
            m_pool_input_map[flow.id()] = pool;
        }

        if (!buff_p->is_valid()) {
            LOG(DEBUG) << "Flow " << flow.id() << " Not synced with producer, drop...";
            return true;
        }

        if (!decode_flow(flow.id(), buff_p, decode)) {
            LOG(ERROR) << "Failed decoding flow " << flow;
            return false;
        }
    }
    return true;
}

bool MDecodeThread::decode_flow(uint32_t flow_id, std::shared_ptr<common::shmem_buff> buff, messages::mstream::EventBsReady decode)
{
    auto pDec = m_stream_decoder_vec[flow_id];
    if (pDec == nullptr) {
        LOG(ERROR) << "flow=" << flow_id << " is not listed!";
        return false;
    }

    if (pDec->low_latency && decode.frame_sizes_size() == 0 && buff) {
        LOG(ERROR) << "Can't process decode request for flow " << flow_id
                   << ". It is configured for complete_frame but frame sizes are not provided!";
        return false;
    }

    size_t payload_len = 0;

    if (buff) {
        payload_len = buff->used_size() ? buff->used_size() : buff->buff_size();
        pDec->stats.bytes_recieved += buff->used_size();
    }

    auto &dec_buffers = pDec->pipeline->getBufferList();
    auto pBS = pDec->pipeline->GetBS();

    size_t read_offset = 0;
    bool buff_from_list = false;
    if (!dec_buffers.empty()) {
        LOG(DEBUG) << "flow=" << flow_id << " dec_buffers.size=" << dec_buffers.size();
        set_select_timeout(1);
        auto list_buff = dec_buffers.back().buff;
        if (buff) {
            dec_buffers.push_back(sMemoryBuffer(0, buff, decode));
        }
        buff = dec_buffers.front().buff;
        read_offset = dec_buffers.front().read_offset;
        decode = dec_buffers.front().decode;
        buff_from_list = true;
    } else if (!buff) {
        // Not suppose to happen in low latency mode since the data should always be cleared
        if (pBS && pBS->DataLength >= BS_MIN_SIZE) {
            if (runDecoder(pDec) & STS_DEC_FATAL) {
                return false;
            }
        }
        set_select_timeout(SELECT_TIMEOUT_MSEC);
        return true;
    }

    if (decode.supports_backpressure()) {
        if (m_pool_output_map[flow_id]->get_consecutive_free() < pDec->pipeline->getFrameBytes()*pDec->params.decPipelineAsyncronousDepth) {
            if (buff && !buff_from_list) {
                dec_buffers.push_back(sMemoryBuffer(0, buff, decode));
            }
            return true;
        }
    }

    if (!pDec->low_latency) {
        uint8_t *data_ptr = buff->ptr() + read_offset;
        payload_len = buff->used_size() ? buff->used_size() : buff->buff_size();
        payload_len -= read_offset;

        size_t copy_size = copyBsData(pDec, data_ptr, payload_len);

        if (!buff_from_list && payload_len > copy_size) {
            dec_buffers.push_back(sMemoryBuffer(copy_size, buff, decode));
            LOG(DEBUG) << "flow=" << flow_id << " insert! dec_buffers.size=" << dec_buffers.size();
        } else if (buff_from_list && payload_len > copy_size) {
            dec_buffers.front().read_offset += copy_size;
        } else if (buff_from_list) {
            dec_buffers.front().buff = nullptr;
            dec_buffers.pop_front();
            LOG(DEBUG) << "flow=" << flow_id << " delete! dec_buffers.size=" << dec_buffers.size();
        }

        if (pBS->DataLength >= BS_MIN_SIZE) {
            if (runDecoder(pDec) & STS_DEC_FATAL) {
                return false;
            }
        }
    } else { // low latency
        uint8_t *data_ptr = buff->ptr();
        payload_len = buff->used_size() ? buff->used_size() : buff->buff_size();

        auto pBS = pDec->pipeline->GetBS();
        int ret_sts;
        uint32_t frame_index = 0;
        if (buff_from_list) {
            frame_index = dec_buffers.front().last_used_frame;
        }
        while (frame_index < (uint32_t)decode.frame_sizes_size()) {

            uint32_t frame_size = decode.frame_sizes(frame_index);
            pBS->Data = data_ptr + read_offset;
            pBS->DataLength = frame_size;
            pBS->DataOffset = 0;

            ret_sts = runDecoder(pDec);

            pBS->DataLength = 0;
            pBS->Data = nullptr;

            if (ret_sts & STS_DEC_FATAL) {
                return false;
            } else if (ret_sts & STS_DEC_DIDNT_CONSUME) {
                break;
            } else if (ret_sts & STS_DEC_BUSY) {
                read_offset += frame_size;
                frame_index++;
                break;
            }

            read_offset += frame_size;
            frame_index++;
        }

        if (!buff_from_list && ((uint32_t)decode.frame_sizes_size() > frame_index)) {
            dec_buffers.push_back(sMemoryBuffer(read_offset, buff, decode));
            dec_buffers.front().last_used_frame = frame_index;
            LOG(DEBUG) << "flow=" << flow_id << " insert! dec_buffers.size=" << dec_buffers.size();
        } else if (buff_from_list && ((uint32_t)decode.frame_sizes_size() > frame_index)) {
            dec_buffers.front().read_offset = read_offset;
            dec_buffers.front().last_used_frame = frame_index;
        } else if (buff_from_list && ((uint32_t)decode.frame_sizes_size() <= frame_index)) {
            dec_buffers.front().buff = nullptr;
            dec_buffers.pop_front();
            LOG(DEBUG) << "flow=" << flow_id << " delete! dec_buffers.size=" << dec_buffers.size();
        }
    }

    return true;
}

void MDecodeThread::handle_enable() {}

void MDecodeThread::handle_disable()
{
    for (auto &elem : m_stream_decoder_vec) {
        auto &dec_buffers = elem.second->pipeline->getBufferList();
        while (!dec_buffers.empty()) {
            dec_buffers.front().buff = nullptr;
            dec_buffers.pop_front();
        }
    }
}

bool MDecodeThread::global_config(const messages::mgmt::GlobalConfig global_config)
{
    if (!common::string_utils::caseless_eq(global_config.module_name(), m_module_name)) {
        // ignore configs that wasnt sent to me
        return true;
    }

    if (!global_config.log_level().empty()) {
        LOG(INFO) << "received SET_LOG_LEVEL request: " << global_config.log_level();
        m_pLogger->set_log_level(global_config.log_level());
    }

    if (!global_config.dump_path().empty()) {
        LOG(INFO) << "received dump_path: " << m_dump_path;

        std::string dump_path = global_config.dump_path();
        if (!dump_path.empty()) {
            if (dump_path.compare(dump_path.size() - 1, 1, "/") != 0) {
                dump_path += std::string("/");
            }
            if (!os_utils::make_dir(dump_path)) {
                LOG(ERROR) << "can't create dum_dump_output_pat directory: " << dump_path;
                return false;
            }
        }
        m_dump_path = dump_path;

        for (auto dec_it : m_stream_decoder_vec) {
            auto dec = dec_it.second;

            std::string output_fname;
            output_fname = m_dump_path + std::string("flow_") + std::to_string(dec->params.flow_id) + "." +
                           std::string(dec->params.output_format);
            msdk_opt_read(output_fname.c_str(), dec->params.strDstFile);

            dec->frame_writer = make_unique<CSmplYUVWriter>();
            dec->frame_writer->Init(dec->params.strDstFile, 1);
        }
    }

    global_config.optional_config().UnpackTo(&m_global_config);

    return true;
}
