
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

#include "mfx_samples_config.h"
#include "sample_defs.h"
#include <algorithm>

#include "stream_pipeline_decode.h"
#include "sysmem_allocator.h"
#include <algorithm>
#include <ctime>

#include "common_string_utils.h"

#include "vaapi_allocator.h"
#include "vaapi_device.h"
#include "vaapi_utils.h"
#include "version.h"

#pragma warning(disable : 4100)

#define __SYNC_WA // avoid sync issue on Media SDK side

#define CHECK_STATUS_LOG(STS, ERROR_MSG)                                                                                           \
    if (sts < MFX_ERR_NONE) {                                                                                                      \
        LOG(ERROR) << std::string(ERROR_MSG) << " sts:" << StatusToString(sts);                                                    \
        return sts;                                                                                                                \
    }
#define CHECK_STATUS_LOG_NO_RET(STS, ERROR_MSG)                                                                                    \
    if (sts < MFX_ERR_NONE) {                                                                                                      \
        LOG(ERROR) << std::string(ERROR_MSG) << " sts:" << StatusToString(sts);                                                    \
    }
#define CHECK_STATUS_LOG_SAFE(STS, ERROR_MSG, DEL_CODE)                                                                            \
    if (sts < MFX_ERR_NONE) {                                                                                                      \
        LOG(ERROR) << std::string(ERROR_MSG) << " sts:" << StatusToString(sts);                                                    \
        DEL_CODE;                                                                                                                  \
        return sts;                                                                                                                \
    }

CStreamDecodingPipeline::CStreamDecodingPipeline()
{
    m_initialized = false;
    m_export_mode = 0;
    m_bVppIsUsed = false;

    m_pmfxDEC = NULL;
    m_pmfxVPP = NULL;
    m_impl = 0;

    m_pGeneralAllocator = NULL;
    m_pmfxAllocatorParams = NULL;
    m_memType = SYSTEM_MEMORY;
    m_bExternalAlloc = false;
    m_bDecOutSysmem = false;

    m_pCurrentFreeSurface = NULL;
    m_pCurrentFreeVppSurface = NULL;
    m_pCurrentFreeOutputSurface = NULL;
    m_pCurrentOutputSurface = NULL;

    m_bIsCompleteFrame = false;
    m_fourcc = 0;

    m_vppOutWidth = 0;
    m_vppOutHeight = 0;

    MSDK_ZERO_MEMORY(m_VppDoNotUse);
    m_VppDoNotUse.Header.BufferId = MFX_EXTBUFF_VPP_DONOTUSE;
    m_VppDoNotUse.Header.BufferSz = sizeof(m_VppDoNotUse);

    MSDK_ZERO_MEMORY(m_VppVideoSignalInfo);
    m_VppVideoSignalInfo.Header.BufferId = MFX_EXTBUFF_VPP_VIDEO_SIGNAL_INFO;
    m_VppVideoSignalInfo.Header.BufferSz = sizeof(m_VppVideoSignalInfo);

    MSDK_ZERO_MEMORY(m_DecodeErrorReport);
    m_DecodeErrorReport.Header.BufferId = MFX_EXTBUFF_DECODE_ERROR_REPORT;

    MSDK_ZERO_MEMORY(m_DecoderPostProcessing);
    m_DecoderPostProcessing.Header.BufferId = MFX_EXTBUFF_DEC_VIDEO_PROCESSING;
    m_DecoderPostProcessing.Header.BufferSz = sizeof(mfxExtDecVideoProcessing);

    m_hwdev = NULL;

    m_bOutI420 = false;

    m_export_mode = vaapiAllocatorParams::DONOT_EXPORT;
    m_libvaBackend = 0;

    m_deliverDecodedFrameCLBK = nullptr;
    m_bufferList.clear();
    m_ExtBuffers.clear();
    m_ExtBuffersMfxBS.clear();
    m_VppExtParams.clear();
}

CStreamDecodingPipeline::~CStreamDecodingPipeline() { Close(); }

mfxStatus CStreamDecodingPipeline::InitialInit(sStreamInputParams *pParams, uint64_t client_context)
{
    MSDK_CHECK_POINTER(pParams, MFX_ERR_NULL_PTR);

    mfxStatus sts = MFX_ERR_NONE;

    m_codecType = pParams->videoType;
    m_flow_id = pParams->flow_id;
    m_client_context = client_context;
    m_bIsCompleteFrame = false;
    m_fourcc = pParams->videoFourcc;

    if (pParams->frameWidth)
        m_vppOutWidth = pParams->frameWidth;
    if (pParams->frameHeight)
        m_vppOutHeight = pParams->frameHeight;

    m_bOutI420 = pParams->outI420;

    mfxInitParam initPar;
    mfxExtThreadsParam threadsPar;
    mfxExtBuffer *extBufs[1];
    mfxVersion version; // real API version with which library is initialized

    MSDK_ZERO_MEMORY(initPar);
    MSDK_ZERO_MEMORY(threadsPar);

    initPar.Version.Major = 1;
    initPar.Version.Minor = 0;

    init_ext_buffer(threadsPar);

    bool needInitExtPar = false;

    if (pParams->decThreadNum) {
        threadsPar.NumThread = pParams->decThreadNum;
        needInitExtPar = true;
    }
    if (pParams->decSchedulingType) {
        threadsPar.SchedulingType = pParams->decSchedulingType;
        needInitExtPar = true;
    }
    if (pParams->decPriority) {
        threadsPar.Priority = pParams->decPriority;
        needInitExtPar = true;
    }
    if (needInitExtPar) {
        extBufs[0] = (mfxExtBuffer *)&threadsPar;
        initPar.ExtParam = extBufs;
        initPar.NumExtParam = 1;
    }

    // Init session
    if (pParams->useHWLib) {
        initPar.Implementation = MFX_IMPL_HARDWARE_ANY; // try searching on all display adapters
        sts = m_mfxSession.InitEx(
            initPar); // Library should pick first available compatible adapter during InitEx call with MFX_IMPL_HARDWARE_ANY
    } else {
        initPar.Implementation = MFX_IMPL_SOFTWARE;
        sts = m_mfxSession.InitEx(initPar);
    }

    CHECK_STATUS_LOG(sts, "m_mfxSession.Init() failed");

    sts = m_mfxSession.QueryVersion(&version);
    CHECK_STATUS_LOG(sts, "QueryVersion() failed");

    sts = m_mfxSession.QueryIMPL(&m_impl);
    CHECK_STATUS_LOG(sts, "QueryIMPL() failed");

    if (pParams->useLowLatencyMode && !CheckVersion(&version, MSDK_FEATURE_LOW_LATENCY)) {
        LOG(ERROR) << "Low Latency mode not supported in the" << version.Major << "." << version.Minor;
        return MFX_ERR_UNSUPPORTED;
    }

    // create decoder
    m_pmfxDEC = new MFXVideoDECODE(m_mfxSession);
    MSDK_CHECK_POINTER(m_pmfxDEC, MFX_ERR_MEMORY_ALLOC);

    // set video type in parameters
    m_mfxVideoParams.mfx.CodecId = pParams->videoType;

    // prepare bit stream
    if (pParams->useLowLatencyMode) {
        m_bIsCompleteFrame = true;
        m_mfxBS.MaxLength = (uint32_t)-1;
        m_mfxBS.DataFlag |= MFX_BITSTREAM_COMPLETE_FRAME;
    } else {
        m_mfxBS.Extend(BS_INIT_SIZE);
    }

    if (CheckVersion(&version, MSDK_FEATURE_PLUGIN_API)) {
        mfxIMPL hw_impl = pParams->useHWLib ? MFX_IMPL_HARDWARE : MFX_IMPL_SOFTWARE;
        auto video_type = pParams->videoType;
        const char *plugin_path = pParams->pluginParams.strPluginPath;
        size_t plugin_path_len = msdk_strnlen(plugin_path, sizeof(plugin_path));
        if ((pParams->pluginParams.type == MFX_PLUGINLOAD_TYPE_FILE) && (plugin_path_len > 0)) {
            m_pUserModule.reset(new MFXVideoUSER(m_mfxSession));
            bool plugin_supported = (video_type == MFX_CODEC_HEVC || video_type == MFX_CODEC_VP8 || video_type == MFX_CODEC_VP9);
            if (plugin_supported) {
                m_pPlugin.reset(LoadPlugin(MFX_PLUGINTYPE_VIDEO_DECODE, m_mfxSession, pParams->pluginParams.pluginGuid, 1,
                                           plugin_path, (mfxU32)plugin_path_len));
            }
            if (m_pPlugin.get() == NULL)
                return MFX_ERR_UNSUPPORTED;
        } else {
            if (AreGuidsEqual(pParams->pluginParams.pluginGuid, MSDK_PLUGINGUID_NULL)) {
                pParams->pluginParams.pluginGuid = msdkGetPluginUID(hw_impl, MSDK_VDECODE, video_type);
                LOG(INFO) << "Using default plugin";
            }
            if (!AreGuidsEqual(pParams->pluginParams.pluginGuid, MSDK_PLUGINGUID_NULL)) {
                LOG(INFO) << "Using explicitly specified plugin";
                m_pPlugin.reset(LoadPlugin(MFX_PLUGINTYPE_VIDEO_DECODE, m_mfxSession, pParams->pluginParams.pluginGuid, 1));
                if (m_pPlugin.get() == NULL) {
                    LOG(ERROR) << "Plugin can't be loaded";
                    return MFX_ERR_UNSUPPORTED;
                }
            }
        }
        CHECK_STATUS_LOG(sts, "Plugin load() failed");
    }

    if (pParams->errorReport) {
        m_ExtBuffersMfxBS.push_back((mfxExtBuffer *)&m_DecodeErrorReport);
        m_mfxBS.ExtParam = reinterpret_cast<mfxExtBuffer **>(&m_ExtBuffersMfxBS[0]);
        m_mfxBS.NumExtParam = static_cast<mfxU16>(m_ExtBuffersMfxBS.size());
    }

    m_initialized = false;
    return sts;
}

mfxStatus CStreamDecodingPipeline::InitalAllocation()
{
    mfxStatus sts = CreateAllocator();
    if (sts < MFX_ERR_NONE) {
        LOG(ERROR) << "CreateAllocator failed";
        return sts;
    }

    sts = AllocFrames();
    if (sts < MFX_ERR_NONE) {
        LOG(ERROR) << "AllocFrames failed";
        return sts;
    }

    sts = m_pmfxDEC->Init(&m_mfxVideoParams);
    if (MFX_WRN_PARTIAL_ACCELERATION == sts) {
        LOG(WARNING) << "MFX_WRN_PARTIAL_ACCELERATION";
        MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
    } else if (sts < MFX_ERR_NONE) {
        LOG(ERROR) << "m_pmfxDEC->Init failed";
        return sts;
    }

    if (!m_bVppIsUsed) {
        return sts;
    }

    sts = m_pmfxVPP->Init(&m_mfxVppVideoParams);
    if (MFX_WRN_PARTIAL_ACCELERATION == sts) {
        LOG(WARNING) << "partial acceleration";
        MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
    } else if (sts < MFX_ERR_NONE) {
        LOG(ERROR) << "m_pmfxVPP->Init failed";
        return sts;
    }

    return sts;
}

mfxStatus CStreamDecodingPipeline::BsInit(sStreamInputParams *pParams)
{
    MSDK_CHECK_POINTER(pParams, MFX_ERR_NULL_PTR);

    mfxStatus sts = MFX_ERR_NONE;

    // Populate parameters. Involves DecodeHeader call
    sts = InitMfxParams(pParams);
    CHECK_STATUS_LOG(sts, "InitMfxParams() failed");
    if (MFX_ERR_MORE_DATA == sts)
        return sts;

    m_bDecOutSysmem = (m_bVppIsUsed) ? (pParams->useHWLib ? false : true) : (m_memType == SYSTEM_MEMORY);

    if (m_bVppIsUsed) {
        LOG(INFO) << "Initializing CPU SW - MFXVideoVPP()";
        m_pmfxVPP = new MFXVideoVPP(m_mfxSession);
        if (!m_pmfxVPP)
            return MFX_ERR_MEMORY_ALLOC;
    }

    // create device and allocator
    m_libvaBackend = pParams->videoAccelerationLib;

    sts = InitalAllocation();
    CHECK_STATUS_LOG(sts, "InitalAllocation() failed");

    sts = m_pmfxDEC->GetVideoParam(&m_mfxVideoParams);
    CHECK_STATUS_LOG(sts, "m_pmfxDEC->GetVideoParam() failed");

    return sts;
}

void CStreamDecodingPipeline::Close()
{
    // WipeMfxBitstream(&m_mfxBS);
    MSDK_SAFE_DELETE(m_pmfxDEC);
    MSDK_SAFE_DELETE(m_pmfxVPP);

    DeleteFrames();

    m_ExtBuffersMfxBS.clear();

    m_pPlugin.reset();
    m_mfxSession.Close();

    MSDK_SAFE_DELETE_ARRAY(m_VppDoNotUse.AlgList);

    // allocator if used as external for MediaSDK must be deleted after decoder
    DeleteAllocator();

    return;
}

mfxStatus CStreamDecodingPipeline::PrepDecoderPostProcessing(sStreamInputParams *pParams)
{
    mfxStatus sts = MFX_ERR_NONE;
    m_bVppIsUsed = true;
    // check decoder post processing mode
    if (((MODE_DECODER_POSTPROC_AUTO == pParams->decPostProcessing) ||
         (MODE_DECODER_POSTPROC_FORCE == pParams->decPostProcessing)) &&
        (MFX_CODEC_AVC == m_mfxVideoParams.mfx.CodecId) &&                       /* Only for AVC */
        (MFX_PICSTRUCT_PROGRESSIVE == m_mfxVideoParams.mfx.FrameInfo.PicStruct)) /* ...And only for progressive!*/
    {
        auto &in = m_DecoderPostProcessing.In;
        auto &out = m_DecoderPostProcessing.Out;

        m_bVppIsUsed = false;

        in.CropY = 0;
        in.CropX = 0;
        in.CropW = m_mfxVideoParams.mfx.FrameInfo.CropW;
        in.CropH = m_mfxVideoParams.mfx.FrameInfo.CropH;

        out.FourCC = m_mfxVideoParams.mfx.FrameInfo.FourCC;
        out.ChromaFormat = m_mfxVideoParams.mfx.FrameInfo.ChromaFormat;
        out.Width = MSDK_ALIGN16(pParams->frameWidth);
        out.Height = MSDK_ALIGN16(pParams->frameHeight);
        out.CropY = 0;
        out.CropX = 0;
        out.CropW = pParams->frameWidth;
        out.CropH = pParams->frameHeight;

        m_ExtBuffers.push_back((mfxExtBuffer *)&m_DecoderPostProcessing);
        AttachExtParam();
        LOG(INFO) << "HW Decoder's post-processing is used for resizing";
    } else {
        LOG(WARNING) << "SW VPP is post-processing is used for resizing!";
    }

    if (MODE_DECODER_POSTPROC_FORCE == pParams->decPostProcessing) {
        if ((MFX_CODEC_AVC != m_mfxVideoParams.mfx.CodecId) ||
            (MFX_PICSTRUCT_PROGRESSIVE != m_mfxVideoParams.mfx.FrameInfo.PicStruct)) {
            LOG(ERROR) << "decoder post processing (forced) cannot resize!";
            sts = MFX_ERR_UNSUPPORTED;
        }
    }
    if ((m_bVppIsUsed) && (MODE_DECODER_POSTPROC_AUTO == pParams->decPostProcessing)) {
        LOG(WARNING) << "decoder post processing will use VPP\n";
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::InitMfxParams(sStreamInputParams *pParams)
{
    MSDK_CHECK_POINTER(m_pmfxDEC, MFX_ERR_NULL_PTR);
    mfxStatus sts = MFX_ERR_NONE;

    // try to find a sequence header in the stream
    // if header is not found this function exits with error (e.g. if device was lost and there's no header in the remaining stream)

    // trying to find PicStruct information in AVI headers
    if (pParams->videoType == MFX_CODEC_JPEG) {
        MJPEG_AVI_ParsePicStruct(&m_mfxBS);
    }

    if (pParams->errorReport) {
        mfxExtDecodeErrorReport *pDecodeErrorReport =
            (mfxExtDecodeErrorReport *)GetExtBuffer(m_mfxBS.ExtParam, m_mfxBS.NumExtParam, MFX_EXTBUFF_DECODE_ERROR_REPORT);

        if (pDecodeErrorReport)
            pDecodeErrorReport->ErrorTypes = 0;

        // parse bit stream and fill mfx params
        sts = m_pmfxDEC->DecodeHeader(&m_mfxBS, &m_mfxVideoParams);
        PrintDecodeErrorReport(pDecodeErrorReport);
    } else {
        // parse bit stream and fill mfx params
        sts = m_pmfxDEC->DecodeHeader(&m_mfxBS, &m_mfxVideoParams);
    }

    if (!sts) {
        m_bVppIsUsed = false;
        // check if we need to use vpp to resize the frame
        if ((m_mfxVideoParams.mfx.FrameInfo.CropW != pParams->frameWidth) ||
            (m_mfxVideoParams.mfx.FrameInfo.CropH != pParams->frameHeight)) {
            if ((pParams->frameWidth > 0) && (pParams->frameHeight > 0))
                m_bVppIsUsed = true;
            //Check decode mode post process mode, for auto and force mode vpp usage will be set later
            if ((MODE_DECODER_POSTPROC_AUTO == pParams->decPostProcessing) ||
                (MODE_DECODER_POSTPROC_FORCE == pParams->decPostProcessing))
                m_bVppIsUsed = false;
        }
        if (m_fourcc && (m_fourcc != m_mfxVideoParams.mfx.FrameInfo.FourCC))
            m_bVppIsUsed = true;
    }

    if (!sts && !(m_impl & MFX_IMPL_SOFTWARE) &&               // hw lib
        (m_mfxVideoParams.mfx.FrameInfo.BitDepthLuma == 10) && // hevc 10 bit
        (m_mfxVideoParams.mfx.CodecId == MFX_CODEC_HEVC) &&
        AreGuidsEqual(pParams->pluginParams.pluginGuid, MFX_PLUGINID_HEVCD_SW) && // sw hevc decoder
        m_bVppIsUsed) {
        sts = MFX_ERR_UNSUPPORTED;
        LOG(ERROR) << "Combination of (SW HEVC plugin in 10bit mode + HW lib VPP) isn't supported. Use -sw option.";
    }
    if (m_pPlugin.get() && pParams->videoType == CODEC_VP8 && !sts) {
        // force set format to nv12 as the vp8 plugin uses yv12
        m_mfxVideoParams.mfx.FrameInfo.FourCC = MFX_FOURCC_NV12;
    }

    if (MFX_ERR_MORE_DATA == sts) {
        return sts;
    }

    m_mfxVideoParams.mfx.Rotation = MFX_ROTATION_0;

    // check DecodeHeader status
    if (MFX_WRN_PARTIAL_ACCELERATION == sts) {
        LOG(WARNING) << "partial acceleration";
        MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
    }
    CHECK_STATUS_LOG(sts, "m_pmfxDEC->DecodeHeader() failed");

    if (!m_mfxVideoParams.mfx.FrameInfo.FrameRateExtN || !m_mfxVideoParams.mfx.FrameInfo.FrameRateExtD) {
        LOG(INFO) << "pretending that stream is 30fps one";
        m_mfxVideoParams.mfx.FrameInfo.FrameRateExtN = 30;
        m_mfxVideoParams.mfx.FrameInfo.FrameRateExtD = 1;
    }
    if (!m_mfxVideoParams.mfx.FrameInfo.AspectRatioW || !m_mfxVideoParams.mfx.FrameInfo.AspectRatioH) {
        LOG(INFO) << "pretending that aspect ratio is 1:1";
        m_mfxVideoParams.mfx.FrameInfo.AspectRatioW = 1;
        m_mfxVideoParams.mfx.FrameInfo.AspectRatioH = 1;
    }

    // Last check if to enable VPP
    if (!m_bVppIsUsed) {
        // check if resize is needed
        if ((m_mfxVideoParams.mfx.FrameInfo.CropW != pParams->frameWidth && pParams->frameWidth) ||
            (m_mfxVideoParams.mfx.FrameInfo.CropH != pParams->frameHeight && pParams->frameHeight)) {
            PrepDecoderPostProcessing(pParams);
        }
    }

    // Set IOPattern based on mem type
    if (m_bVppIsUsed) {
        m_mfxVideoParams.IOPattern = (mfxU16)(pParams->useHWLib ? MFX_IOPATTERN_OUT_VIDEO_MEMORY : MFX_IOPATTERN_OUT_SYSTEM_MEMORY);
    } else {
        m_mfxVideoParams.IOPattern =
            (mfxU16)(m_memType != SYSTEM_MEMORY ? MFX_IOPATTERN_OUT_VIDEO_MEMORY : MFX_IOPATTERN_OUT_SYSTEM_MEMORY);
    }
    m_mfxVideoParams.AsyncDepth = pParams->decPipelineAsyncronousDepth;
    m_initialized = true;
    return MFX_ERR_NONE;
}

// This function may be called more than once
mfxStatus CStreamDecodingPipeline::AllocAndInitVppFilters()
{
    m_VppDoNotUse.NumAlg = 4;
    if (NULL == m_VppDoNotUse.AlgList)
        m_VppDoNotUse.AlgList = new mfxU32[m_VppDoNotUse.NumAlg];
    if (!m_VppDoNotUse.AlgList)
        return MFX_ERR_NULL_PTR;

    // Set the folowing params to off
    m_VppDoNotUse.AlgList[0] = MFX_EXTBUFF_VPP_DENOISE;
    m_VppDoNotUse.AlgList[1] = MFX_EXTBUFF_VPP_SCENE_ANALYSIS;
    m_VppDoNotUse.AlgList[2] = MFX_EXTBUFF_VPP_DETAIL;
    m_VppDoNotUse.AlgList[3] = MFX_EXTBUFF_VPP_PROCAMP;

    m_VppExtParams.clear();
    m_VppExtParams.push_back((mfxExtBuffer *)&m_VppDoNotUse);

    return MFX_ERR_NONE;
}

mfxStatus CStreamDecodingPipeline::InitVppParams()
{
    mfxStatus sts;
    m_mfxVppVideoParams.vpp.In = m_mfxVideoParams.mfx.FrameInfo;
    m_mfxVppVideoParams.vpp.Out = m_mfxVppVideoParams.vpp.In;
    m_mfxVppVideoParams.AsyncDepth = m_mfxVideoParams.AsyncDepth;

    if (m_bDecOutSysmem)
        m_mfxVppVideoParams.IOPattern = (mfxU16)MFX_IOPATTERN_IN_SYSTEM_MEMORY;
    else
        m_mfxVppVideoParams.IOPattern = (mfxU16)MFX_IOPATTERN_IN_VIDEO_MEMORY;

    if (m_memType != SYSTEM_MEMORY)
        m_mfxVppVideoParams.IOPattern |= MFX_IOPATTERN_OUT_VIDEO_MEMORY;
    else
        m_mfxVppVideoParams.IOPattern |= MFX_IOPATTERN_OUT_SYSTEM_MEMORY;

    if (m_fourcc)
        m_mfxVppVideoParams.vpp.Out.FourCC = m_fourcc;

    if (m_vppOutWidth && m_vppOutHeight) {
        m_mfxVppVideoParams.vpp.Out.CropW = m_vppOutWidth;
        m_mfxVppVideoParams.vpp.Out.Width = MSDK_ALIGN16(m_vppOutWidth);
        m_mfxVppVideoParams.vpp.Out.CropH = m_vppOutHeight;
        if (MFX_PICSTRUCT_PROGRESSIVE == m_mfxVppVideoParams.vpp.Out.PicStruct)
            m_mfxVppVideoParams.vpp.Out.Height = MSDK_ALIGN16(m_vppOutHeight);
        else
            m_mfxVppVideoParams.vpp.Out.Height = MSDK_ALIGN32(m_vppOutHeight);
    }

    sts = AllocAndInitVppFilters();
    CHECK_STATUS_LOG(sts, "AllocAndInitVppFilters() failed");

    m_mfxVppVideoParams.ExtParam = &m_VppExtParams[0];
    m_mfxVppVideoParams.NumExtParam = (mfxU16)m_VppExtParams.size();

    // For P010 video format output surfaces needs to be shifted
    if ((m_memType != SYSTEM_MEMORY) && (m_mfxVppVideoParams.vpp.Out.FourCC == MFX_FOURCC_P010))
        m_mfxVppVideoParams.vpp.Out.Shift = 1;
    return MFX_ERR_NONE;
}

mfxStatus CStreamDecodingPipeline::SetupDecoderVpp(mfxFrameAllocRequest &Request, mfxFrameAllocRequest (&VppRequest)[2])
{
    if (m_bDecOutSysmem)
        m_mfxVideoParams.IOPattern = (mfxU16)MFX_IOPATTERN_OUT_SYSTEM_MEMORY;
    else
        m_mfxVideoParams.IOPattern = (mfxU16)MFX_IOPATTERN_OUT_VIDEO_MEMORY;

    mfxStatus sts = m_pmfxDEC->QueryIOSurf(&m_mfxVideoParams, &Request);
    MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
    CHECK_STATUS_LOG(sts, "m_pmfxDEC->QueryIOSurf() failed");

    sts = InitVppParams();
    CHECK_STATUS_LOG(sts, "InitVppParams() failed");

    sts = m_pmfxVPP->Query(&m_mfxVppVideoParams, &m_mfxVppVideoParams);
    MSDK_IGNORE_MFX_STS(sts, MFX_WRN_INCOMPATIBLE_VIDEO_PARAM);
    CHECK_STATUS_LOG(sts, "m_pmfxVPP->Query() failed");

    sts = m_pmfxVPP->QueryIOSurf(&m_mfxVppVideoParams, VppRequest);
    MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
    CHECK_STATUS_LOG(sts, "m_pmfxVPP->QueryIOSurf() failed");
    for (int i = 0; i < 2; i++) {
        if (VppRequest[i].NumFrameSuggested < m_mfxVppVideoParams.AsyncDepth) {
            return MFX_ERR_MEMORY_ALLOC;
        }
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::AllocVppFrames(mfxFrameAllocRequest (&VppRequest)[2])
{
    mfxStatus sts = MFX_ERR_NONE;
    if (m_bVppIsUsed) {
        if (m_export_mode != vaapiAllocatorParams::DONOT_EXPORT) {
            VppRequest[1].Type |= MFX_MEMTYPE_EXPORT_FRAME;
        }
        VppRequest[1].NumFrameSuggested = VppRequest[1].NumFrameMin = m_nVppSurfNum;
        VppRequest[1].Info = m_mfxVppVideoParams.vpp.Out;

        sts = m_pGeneralAllocator->Alloc(m_pGeneralAllocator->pthis, &VppRequest[1], &m_mfxVppResponse);
        CHECK_STATUS_LOG(sts, "m_pGeneralAllocator->Alloc() failed");

        m_nVppSurfNum = m_mfxVppResponse.NumFrameActual;
        sts = AllocVppBuffers(m_nVppSurfNum);
        CHECK_STATUS_LOG(sts, "AllocVppBuffers() failed");
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::CreateHWDevice()
{
    mfxStatus sts = MFX_ERR_NONE;
    const std::string devicePath = "";
    m_hwdev = CreateVAAPIDevice(devicePath, m_libvaBackend);

    if (NULL == m_hwdev) {
        return MFX_ERR_MEMORY_ALLOC;
    }

    mfxI32 monitorType = 0;
    sts = m_hwdev->Init(&monitorType, 0, MSDKAdapter::GetNumber(m_mfxSession));
    CHECK_STATUS_LOG(sts, "m_hwdev->Init() failed");
    return MFX_ERR_NONE;
}

mfxStatus CStreamDecodingPipeline::ResetDevice() { return m_hwdev->Reset(); }

mfxStatus CStreamDecodingPipeline::AllocFrames()
{
    MSDK_CHECK_POINTER(m_pmfxDEC, MFX_ERR_NULL_PTR);

    m_nSurfNum = 0;
    m_nVppSurfNum = 0;
    mfxStatus sts = MFX_ERR_NONE;
    mfxFrameAllocRequest Request;
    MSDK_ZERO_MEMORY(Request);
    mfxFrameAllocRequest VppRequest[2];
    MSDK_ZERO_MEMORY(VppRequest[0]);
    MSDK_ZERO_MEMORY(VppRequest[1]);

    sts = m_pmfxDEC->Query(&m_mfxVideoParams, &m_mfxVideoParams);
    MSDK_IGNORE_MFX_STS(sts, MFX_WRN_INCOMPATIBLE_VIDEO_PARAM);
    CHECK_STATUS_LOG(sts, "m_pmfxDEC->Query() failed");

    sts = m_pmfxDEC->QueryIOSurf(&m_mfxVideoParams, &Request);
    if (MFX_WRN_PARTIAL_ACCELERATION == sts) {
        LOG(WARNING) << "QueryIOSurf returned partial acceleration";
        MSDK_IGNORE_MFX_STS(sts, MFX_WRN_PARTIAL_ACCELERATION);
        m_bDecOutSysmem = true;
    }
    CHECK_STATUS_LOG(sts, "m_pmfxDEC->QueryIOSurf() failed");

    if (m_bVppIsUsed) {
        sts = SetupDecoderVpp(Request, VppRequest);
        CHECK_STATUS_LOG(sts, "SetupDecoderVpp() failed");

        // Calculate the number of surfaces needed by vpp input and decode output
        m_nSurfNum = Request.NumFrameSuggested + VppRequest[0].NumFrameSuggested - m_mfxVideoParams.AsyncDepth + 1;
        m_nVppSurfNum = VppRequest[1].NumFrameSuggested;

        Request.NumFrameSuggested = Request.NumFrameMin = m_nSurfNum;
        Request.Type = MFX_MEMTYPE_EXTERNAL_FRAME | MFX_MEMTYPE_FROM_DECODE | MFX_MEMTYPE_FROM_VPPIN;
    } else if (m_export_mode != vaapiAllocatorParams::DONOT_EXPORT) {
        Request.Type |= MFX_MEMTYPE_EXPORT_FRAME;
    }
    if (m_bDecOutSysmem)
        Request.Type |= MFX_MEMTYPE_SYSTEM_MEMORY;
    else
        Request.Type |= MFX_MEMTYPE_VIDEO_MEMORY_DECODER_TARGET;

    if ((Request.NumFrameSuggested < m_mfxVideoParams.AsyncDepth) && (m_impl & MFX_IMPL_HARDWARE_ANY))
        return MFX_ERR_MEMORY_ALLOC;

    // alloc frames for decoder
    sts = m_pGeneralAllocator->Alloc(m_pGeneralAllocator->pthis, &Request, &m_mfxResponse);
    CHECK_STATUS_LOG(sts, "m_pGeneralAllocator->Alloc() failed");

    sts = AllocVppFrames(VppRequest);
    CHECK_STATUS_LOG(sts, "AllocVppFrames()");

    m_nSurfNum = m_mfxResponse.NumFrameActual;

    sts = AllocBuffers(m_nSurfNum);
    CHECK_STATUS_LOG(sts, "AllocBuffers() failed");

    sts = SetupSurfaces(Request);
    CHECK_STATUS_LOG(sts, "SetupSurfaces() failed");

    sts = SetupVppSurfaces(VppRequest);
    CHECK_STATUS_LOG(sts, "SetupSurfaces() failed");

    return MFX_ERR_NONE;
}

mfxStatus CStreamDecodingPipeline::CreateAllocator()
{
    mfxStatus sts = MFX_ERR_NONE;
    VADisplay va_display = NULL;

    m_pGeneralAllocator = new GeneralAllocator();

    if ((!m_bDecOutSysmem) || (m_memType != SYSTEM_MEMORY) || (MFX_IMPL_HARDWARE == MFX_IMPL_BASETYPE(m_impl))) {
        sts = CreateHWDevice();
        CHECK_STATUS_LOG(sts, "CreateHWDevice() failed");

        // Find and set device manager
        sts = m_hwdev->GetHandle(MFX_HANDLE_VA_DISPLAY, (mfxHDL *)&va_display);
        CHECK_STATUS_LOG(sts, "m_hwdev->GetHandle() failed");
        sts = m_mfxSession.SetHandle(MFX_HANDLE_VA_DISPLAY, va_display);
        CHECK_STATUS_LOG(sts, "m_mfxSession.SetHandle() failed");
    }

    if ((!m_bDecOutSysmem) || (m_memType != SYSTEM_MEMORY)) {

        vaapiAllocatorParams *p_vaapiAllocParams = new vaapiAllocatorParams;
        MSDK_CHECK_POINTER(p_vaapiAllocParams, MFX_ERR_MEMORY_ALLOC);

        p_vaapiAllocParams->m_dpy = va_display;
        m_export_mode = p_vaapiAllocParams->m_export_mode;
        m_pmfxAllocatorParams = p_vaapiAllocParams;

        sts = m_mfxSession.SetFrameAllocator(m_pGeneralAllocator);
        CHECK_STATUS_LOG(sts, "m_mfxSession.SetFrameAllocator() failed");

        m_bExternalAlloc = true;
    }

    sts = m_pGeneralAllocator->Init(m_pmfxAllocatorParams);
    CHECK_STATUS_LOG(sts, "m_pGeneralAllocator->Init() failed");
    return MFX_ERR_NONE;
}

void CStreamDecodingPipeline::DeleteFrames()
{
    FreeBuffers();

    m_pCurrentFreeSurface = NULL;
    MSDK_SAFE_FREE(m_pCurrentFreeOutputSurface);

    m_pCurrentFreeVppSurface = NULL;

    // delete frames
    if (m_pGeneralAllocator) {
        m_pGeneralAllocator->Free(m_pGeneralAllocator->pthis, &m_mfxResponse);
    }

    return;
}

// delete allocator
void CStreamDecodingPipeline::AttachExtParam()
{
    auto extParam = reinterpret_cast<mfxExtBuffer **>(&m_ExtBuffers[0]);
    m_mfxVideoParams.ExtParam = extParam;
    m_mfxVideoParams.NumExtParam = m_ExtBuffers.size();
}

void CStreamDecodingPipeline::DeleteAllocator()
{
    MSDK_SAFE_DELETE(m_pGeneralAllocator);
    MSDK_SAFE_DELETE(m_pmfxAllocatorParams);
    MSDK_SAFE_DELETE(m_hwdev);
}

mfxStatus CStreamDecodingPipeline::DeliverOutput(mfxFrameSurface1 *frame)
{
    mfxStatus res = MFX_ERR_NONE, sts = MFX_ERR_NONE;

    if (!frame) {
        return MFX_ERR_NULL_PTR;
    }

    if (m_bExternalAlloc) {
        res = m_pGeneralAllocator->Lock(m_pGeneralAllocator->pthis, frame->Data.MemId, &(frame->Data));
        if (MFX_ERR_NONE == res) {
            //
            if (m_deliverDecodedFrameCLBK)
                m_deliverDecodedFrameCLBK(frame, m_flow_id, m_client_context);
            //
            sts = m_pGeneralAllocator->Unlock(m_pGeneralAllocator->pthis, frame->Data.MemId, &(frame->Data));
        }
        if ((MFX_ERR_NONE == res) && (MFX_ERR_NONE != sts)) {
            res = sts;
        }
    } else {
        if (m_deliverDecodedFrameCLBK)
            m_deliverDecodedFrameCLBK(frame, m_flow_id, m_client_context);
    }
    return res;
}

mfxStatus CStreamDecodingPipeline::SetupSurfaces(mfxFrameAllocRequest &Request)
{
    mfxStatus sts = MFX_ERR_NONE;
    for (int i = 0; i < m_nSurfNum; i++) {
        m_pSurfaces[i].frame.Info = Request.Info;
        if (m_bExternalAlloc) {
            m_pSurfaces[i].frame.Data.MemId = m_mfxResponse.mids[i];
        } else {
            sts = m_pGeneralAllocator->Lock(m_pGeneralAllocator->pthis, m_mfxResponse.mids[i], &(m_pSurfaces[i].frame.Data));
            CHECK_STATUS_LOG(sts, "SetupSurfaces() m_pGeneralAllocator->Lock() failed");
        }
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::SetupVppSurfaces(mfxFrameAllocRequest (&VppRequest)[2])
{
    mfxStatus sts = MFX_ERR_NONE;
    for (int i = 0; i < m_nVppSurfNum; i++) {
        m_pVppSurfaces[i].frame.Info = VppRequest[1].Info;
        if (m_bExternalAlloc) {
            m_pVppSurfaces[i].frame.Data.MemId = m_mfxVppResponse.mids[i];
        } else {
            sts = m_pGeneralAllocator->Lock(m_pGeneralAllocator->pthis, m_mfxVppResponse.mids[i], &(m_pVppSurfaces[i].frame.Data));
            CHECK_STATUS_LOG(sts, "SetupVppSurfaces() m_pGeneralAllocator->Lock() failed");
        }
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::CallSyncOutputSurface()
{
    mfxStatus curr_sts;
    if (m_codecType == MFX_CODEC_JPEG)
        curr_sts = SyncOutputSurface(1000000);
    else
        curr_sts = SyncOutputSurface(0);
    // everything is an error at this point
    if (MFX_ERR_NONE == curr_sts) {
        curr_sts = MFX_WRN_DEVICE_BUSY;
    } else {
        if (MFX_ERR_MORE_DATA == curr_sts) {
            // can't get MFX_ERR_MORE_DATA and have no output - not suppose to happen
            curr_sts = MFX_WRN_DEVICE_BUSY;
        }
    }
    return curr_sts;
}

mfxStatus CStreamDecodingPipeline::SyncOutputSurface(mfxU32 wait)
{
    if (!m_pCurrentOutputSurface) {
        m_pCurrentOutputSurface = m_OutputSurfacesPool.GetSurface();
    }
    if (!m_pCurrentOutputSurface) {
        return MFX_ERR_MORE_DATA;
    }

    mfxStatus sts = m_mfxSession.SyncOperation(m_pCurrentOutputSurface->syncp, wait);

    if (MFX_ERR_GPU_HANG == sts) {
        LOG(ERROR) << "GPU hang happened";
        // Output surface can be corrupted
        // But should be delivered to output anyway
        sts = MFX_ERR_NONE;
    }

    if (MFX_ERR_NONE == sts) { // we got completely decoded frame //

        sts = DeliverOutput(&(m_pCurrentOutputSurface->surface->frame));
        if (MFX_ERR_NONE != sts) {
            sts = MFX_ERR_UNKNOWN;
        }

        ReturnSurfaceToBuffers(m_pCurrentOutputSurface);
        m_pCurrentOutputSurface = NULL;
    }

    return sts;
}

mfxStatus CStreamDecodingPipeline::ExecutVppFunction(mfxFrameSurface1 *pOutSurface)
{
    mfxStatus sts = MFX_ERR_NONE;
    auto &frame_info = m_pCurrentFreeVppSurface->frame.Info;

    frame_info.FrameId.ViewId = pOutSurface->Info.FrameId.ViewId; // explicitly copy ViewId
    if (pOutSurface->Info.PicStruct != frame_info.PicStruct) {
        frame_info.PicStruct = pOutSurface->Info.PicStruct;
    }
    if ((frame_info.CropW == 0) || (frame_info.CropH == 0)) {
        frame_info.CropW = pOutSurface->Info.CropW;
        frame_info.CropH = pOutSurface->Info.CropH;
        frame_info.CropX = pOutSurface->Info.CropX;
        frame_info.CropY = pOutSurface->Info.CropY;
    }
    if ((pOutSurface->Info.PicStruct == 0) && (frame_info.PicStruct == 0)) {
        frame_info.PicStruct = MFX_PICSTRUCT_PROGRESSIVE;
        pOutSurface->Info.PicStruct = MFX_PICSTRUCT_PROGRESSIVE;
    }

    sts = m_pmfxVPP->RunFrameVPPAsync(pOutSurface, &(m_pCurrentFreeVppSurface->frame), NULL, &(m_pCurrentFreeOutputSurface->syncp));

    if (MFX_WRN_DEVICE_BUSY == sts) {
        LOG(INFO) << "MSDK_SLEEP(1) --> MFX_WRN_DEVICE_BUSY";
        MSDK_SLEEP(1);
    }
    return sts;
}

mfxStatus CStreamDecodingPipeline::RunDecoder()
{
    mfxFrameSurface1 *pOutSurface = NULL;
    mfxBitstream *pBitstream = &m_mfxBS;
    mfxExtDecodeErrorReport *pDecodeErrorReport = NULL;
    bool bErrIncompatibleVideoParams = false;
    mfxStatus sts = MFX_ERR_NONE;

    SyncOutputSurface(0);
    SyncFrameSurfaces();
    SyncVppFrameSurfaces();
    if (!m_pCurrentFreeSurface) {
        m_pCurrentFreeSurface = m_FreeSurfacesPool.GetSurface();
    }
    if (m_bVppIsUsed && !m_pCurrentFreeVppSurface) {
        m_pCurrentFreeVppSurface = m_FreeVppSurfacesPool.GetSurface();
    }

    if (!m_pCurrentFreeSurface || (!m_pCurrentFreeVppSurface && m_bVppIsUsed) ||
        (m_OutputSurfacesPool.GetSurfaceCount() == m_mfxVideoParams.AsyncDepth)) {
        // we stuck with no free surface available, now we will sync...
        sts = SyncOutputSurface(0);
        //
        if (MFX_ERR_MORE_DATA == sts) {
            sts = MFX_ERR_NOT_FOUND;
            LOG(ERROR) << "fatal: failed to find output surface, that's a bug";
            return sts;
        }
        // note: MFX_WRN_IN_EXECUTION will also be treated as an error at this point
        if (!m_pCurrentFreeSurface) {
            m_pCurrentFreeSurface = m_FreeSurfacesPool.GetSurface();
        }
        if (m_bVppIsUsed && !m_pCurrentFreeVppSurface) {
            m_pCurrentFreeVppSurface = m_FreeVppSurfacesPool.GetSurface();
        }

        if (!m_pCurrentFreeSurface || (!m_pCurrentFreeVppSurface && m_bVppIsUsed) ||
            (m_OutputSurfacesPool.GetSurfaceCount() == m_mfxVideoParams.AsyncDepth)) {
            LOG(INFO) << "No more surfaces to continue";
            return MFX_ERR_MORE_SURFACE;
        }
    }

    if (!m_pCurrentFreeOutputSurface) {
        m_pCurrentFreeOutputSurface = GetFreeOutputSurface();
    }
    if (!m_pCurrentFreeOutputSurface) {
        sts = MFX_ERR_NOT_FOUND;
        LOG(ERROR) << "MFX_ERR_NOT_FOUND";
        return sts;
    }

    if ((MFX_ERR_NONE == sts) || (MFX_ERR_MORE_DATA == sts) || (MFX_ERR_MORE_SURFACE == sts)) {
        if (pBitstream) {
            pDecodeErrorReport = (mfxExtDecodeErrorReport *)GetExtBuffer(pBitstream->ExtParam, pBitstream->NumExtParam,
                                                                         MFX_EXTBUFF_DECODE_ERROR_REPORT);
        }
        sts = m_pmfxDEC->DecodeFrameAsync(pBitstream, &(m_pCurrentFreeSurface->frame), &pOutSurface,
                                          &(m_pCurrentFreeOutputSurface->syncp));
        PrintDecodeErrorReport(pDecodeErrorReport);

        if (MFX_WRN_DEVICE_BUSY == sts) {
            if (m_bIsCompleteFrame) {
                LOG(INFO) << "MFX_WRN_DEVICE_BUSY - latency increased";
            }
            sts = CallSyncOutputSurface();
        }
        if (MFX_WRN_DEVICE_BUSY == sts) {
            return sts;
        }

        if (m_bIsCompleteFrame && pBitstream->DataLength < 4) {
            // There might be NALU footer of 3 bytes that might not be consumed. ignore this as it is not an error.
            pBitstream->DataLength = 0;
        }

        if (sts > MFX_ERR_NONE) {
            if (m_pCurrentFreeOutputSurface->syncp) {
                MSDK_SELF_CHECK(pOutSurface);
                sts = MFX_ERR_NONE; // we have an output ready
            } else {
                sts = MFX_ERR_MORE_SURFACE; // we do not have an output ready
            }
        } else if (pBitstream && (MFX_ERR_MORE_DATA == sts)) {
            if (pBitstream->DataLength > 0 && m_bIsCompleteFrame) {
                LOG(ERROR) << "Bad decoder behavior, in low latency mode. bitstream length is not 0.";
                return MFX_ERR_UNDEFINED_BEHAVIOR;
            }
        } else if (MFX_ERR_INCOMPATIBLE_VIDEO_PARAM == sts) {
            bErrIncompatibleVideoParams = true;
            LOG(ERROR) << "MFX_ERR_INCOMPATIBLE_VIDEO_PARAM";
            // need to go to the buffering loop prior to reset procedure
            pBitstream = NULL;
            sts = MFX_ERR_NONE;
        }
    }

    if ((MFX_ERR_NONE == sts) || (MFX_ERR_MORE_DATA == sts) || (MFX_ERR_MORE_SURFACE == sts)) {
        // if current free surface is locked we are moving it to the used surfaces array
        m_UsedSurfacesPool.AddSurface(m_pCurrentFreeSurface);
        m_pCurrentFreeSurface = NULL;
    } else {
        CHECK_STATUS_LOG_NO_RET(sts, "DecodeFrameAsync returned error status");
    }

    if (MFX_ERR_NONE == sts) {
        if (m_bVppIsUsed) {
            if (m_pCurrentFreeVppSurface) {
                do {
                    sts = ExecutVppFunction(pOutSurface);
                } while (MFX_WRN_DEVICE_BUSY == sts);

                // check errors
                if (MFX_ERR_MORE_DATA == sts) { // will never happen actually
                    LOG(ERROR) << "ExecutVppFunction() failed, MFX_ERR_MORE_DATA";
                    return MFX_ERR_MORE_DATA;
                } else if (MFX_ERR_NONE != sts) {
                    LOG(ERROR) << "ExecutVppFunction() failed, other";
                    return sts;
                }

                m_UsedVppSurfacesPool.AddSurface(m_pCurrentFreeVppSurface);
                msdk_atomic_inc16(&(m_pCurrentFreeVppSurface->render_lock));

                m_pCurrentFreeOutputSurface->surface = m_pCurrentFreeVppSurface;
                m_OutputSurfacesPool.AddSurface(m_pCurrentFreeOutputSurface);

                m_pCurrentFreeOutputSurface = NULL;
                m_pCurrentFreeVppSurface = NULL;
            }
        } else {
            LOG(INFO) << "m_bVppIsUsed is false, call FindUsedSurface(pOutSurface)";
            msdkFrameSurface *surface = FindUsedSurface(pOutSurface);

            msdk_atomic_inc16(&(surface->render_lock));

            m_pCurrentFreeOutputSurface->surface = surface;
            m_OutputSurfacesPool.AddSurface(m_pCurrentFreeOutputSurface);
            m_pCurrentFreeOutputSurface = NULL;
        }
    }

    if (m_codecType == MFX_CODEC_JPEG)
        SyncOutputSurface(4000000);

    // if we exited main decoding loop with ERR_INCOMPATIBLE_PARAM we need to send this status to caller
    if (bErrIncompatibleVideoParams) {
        sts = MFX_ERR_INCOMPATIBLE_VIDEO_PARAM;
    }

    return sts;
}
