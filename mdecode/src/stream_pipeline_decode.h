
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

#ifndef __STREAM_PIPELINE_DECODE_H__
#define __STREAM_PIPELINE_DECODE_H__

#include "sample_defs.h"

#if D3D_SURFACES_SUPPORT
#pragma warning(disable : 4201)
#include <d3d9.h>
#include <dxva2api.h>
#endif

#include <list>
#include <memory>
#include <vector>

#include "hw_device.h"
#include "mfx_buffering.h"

#include "base_allocator.h"
#include "sample_utils.h"

#include "mfxmvc.h"
#include "mfxplugin++.h"
#include "mfxplugin.h"
#include "mfxvideo++.h"
#include "mfxvideo.h"
#include "mfxvp8.h"

#include "general_allocator.h"
#include "plugin_loader.h"

#include "easylogging++.h"
#include "common_mem_manager.h"

#include <messages/proto/mstream.pb.h>
#include <messages/proto/types.pb.h>

#define BS_INIT_SIZE (8 * 1024 * 1024)
#define BS_MIN_SIZE (16 * 1024)

#define SYSTEM_MEMORY 0x00
#define D3D9_MEMORY 0x01
#define D3D11_MEMORY 0x02

#define MODE_DECODER_POSTPROC_AUTO 0x1
#define MODE_DECODER_POSTPROC_FORCE 0x2

struct sStreamInputParams {
    uint32_t flow_id = 0;
    mfxU32 videoType = 0;
    bool useHWLib = false;
    bool useLowLatencyMode = false;

    mfxU16 decPostProcessing = 0;
    mfxU16 decPipelineAsyncronousDepth = 0;
    mfxU16 decThreadNum = 0;
    mfxI32 decSchedulingType = 0;
    mfxI32 decPriority = 0;

    mfxU16 frameWidth = 0;
    mfxU16 frameHeight = 0;

    mfxU32 videoFourcc = 0;
    msdk_char output_format[5] = {};
    bool outI420 = false;

    bool errorReport = false;

    mfxI32 videoAccelerationLib = 0;

    msdk_char strDstFile[MSDK_MAX_FILENAME_LEN] = {};
    sPluginParams pluginParams;
};

struct sMemoryBuffer {
    size_t read_offset = 0;
    std::shared_ptr<imif::common::shmem_buff> buff = nullptr;
    imif::messages::mstream::EventBsReady decode;
    uint32_t last_used_frame;

    sMemoryBuffer(size_t read_offset_, std::shared_ptr<imif::common::shmem_buff> buff_,
                  imif::messages::mstream::EventBsReady &decode_)
        : read_offset(read_offset_), buff(buff_), decode(decode_)
    {
        last_used_frame = 0;
    }
};

class CStreamDecodingPipeline : public CBuffering {
public:
    CStreamDecodingPipeline();
    ~CStreamDecodingPipeline();

    mfxStatus InitialInit(sStreamInputParams *pParams, uint64_t client_context = 0);
    mfxStatus InitalAllocation();
    mfxStatus BsInit(sStreamInputParams *pParams);
    bool IsInitialized() { return m_initialized; }
    mfxBitstream *GetBS() { return &m_mfxBS; }
    uint32_t GetFlowInfo() { return m_flow_id; }
    mfxStatus RunDecoder();
    void Close();
    mfxStatus ResetDevice();

    std::list<sMemoryBuffer> &getBufferList() { return m_bufferList; }
    bool busyFlag() { return m_busyFlag; }
    void busyFlag(bool flag) { m_busyFlag = flag; }
    
    void setFrameBytes(size_t size) { m_frameBytes = size; } 
    size_t getFrameBytes() { return m_frameBytes; } 

    void SetDeliverDecodedFrameCLBK(std::function<void(mfxFrameSurface1 *, uint32_t, uint64_t)> clbk)
    {
        m_deliverDecodedFrameCLBK = clbk;
    }

    inline void PrintDecodeErrorReport(mfxExtDecodeErrorReport *pDecodeErrorReport)
    {
        if (pDecodeErrorReport) {
            if (pDecodeErrorReport->ErrorTypes & MFX_ERROR_SPS)
                LOG(ERROR) << "SPS Error detected!";

            if (pDecodeErrorReport->ErrorTypes & MFX_ERROR_PPS)
                LOG(ERROR) << "PPS Error detected!";

            if (pDecodeErrorReport->ErrorTypes & MFX_ERROR_SLICEHEADER)
                LOG(ERROR) << "SliceHeader Error detected!";

            if (pDecodeErrorReport->ErrorTypes & MFX_ERROR_FRAME_GAP)
                LOG(ERROR) << "[Error] Frame Gap Error detected!";
        }
    }

    // functions
protected:
    virtual mfxStatus CreateHWDevice();
    virtual mfxStatus InitMfxParams(sStreamInputParams *pParams);
    virtual void AttachExtParam();
    virtual mfxStatus AllocAndInitVppFilters();
    virtual mfxStatus InitVppParams();
    virtual mfxStatus AllocFrames();
    virtual void DeleteFrames();
    virtual mfxStatus SyncOutputSurface(mfxU32 wait);
    virtual mfxStatus DeliverOutput(mfxFrameSurface1 *frame);
    virtual mfxStatus CreateAllocator();
    virtual void DeleteAllocator();

    mfxStatus SetupDecoderVpp(mfxFrameAllocRequest &Request, mfxFrameAllocRequest (&VppRequest)[2]);
    mfxStatus AllocVppFrames(mfxFrameAllocRequest (&VppRequest)[2]);
    mfxStatus PrepDecoderPostProcessing(sStreamInputParams *pParams);
    mfxStatus CallSyncOutputSurface();
    mfxStatus SetupSurfaces(mfxFrameAllocRequest &Request);
    mfxStatus SetupVppSurfaces(mfxFrameAllocRequest (&VppRequest)[2]);
    mfxStatus ExecutVppFunction(mfxFrameSurface1 *pOutSurface);

    // variables
protected:
    bool m_initialized = false;
    uint32_t m_flow_id = 0;
    uint64_t m_client_context = 0;
    size_t m_frameBytes = 0;
    MFXVideoSession m_mfxSession;
    mfxIMPL m_impl;
    MFXVideoDECODE *m_pmfxDEC = nullptr;
    MFXVideoVPP *m_pmfxVPP = nullptr;
    mfxVideoParam m_mfxVideoParams = {};
    mfxVideoParam m_mfxVppVideoParams = {};
    std::unique_ptr<MFXVideoUSER> m_pUserModule = nullptr;
    std::unique_ptr<MFXPlugin> m_pPlugin = nullptr;
    std::vector<mfxExtBuffer *> m_ExtBuffers;
    std::vector<mfxExtBuffer *> m_ExtBuffersMfxBS;
    mfxExtDecVideoProcessing m_DecoderPostProcessing;
    mfxExtDecodeErrorReport m_DecodeErrorReport;
    mfxBitstreamWrapper m_mfxBS;

    mfxU16 m_nSurfNum = 0;
    mfxU16 m_nVppSurfNum = 0;

    GeneralAllocator *m_pGeneralAllocator = nullptr;
    mfxAllocatorParams *m_pmfxAllocatorParams = nullptr;

    bool m_bDecOutSysmem = false;
    bool m_bExternalAlloc = false;
    mfxFrameAllocResponse m_mfxVppResponse = {};
    mfxFrameAllocResponse m_mfxResponse = {};

    msdkFrameSurface *m_pCurrentFreeSurface = nullptr;
    msdkFrameSurface *m_pCurrentFreeVppSurface = nullptr;
    msdkOutputSurface *m_pCurrentFreeOutputSurface = nullptr;
    msdkOutputSurface *m_pCurrentOutputSurface = nullptr;

    mfxU16 m_memType = SYSTEM_MEMORY;
    bool m_bIsCompleteFrame = false;
    mfxU32 m_fourcc = 0; // color format of vpp out, i420 by default
    bool m_bOutI420 = false;

    mfxU16 m_vppOutWidth = 0;
    mfxU16 m_vppOutHeight = 0;

    bool m_bVppIsUsed = false;

    uint32_t m_codecType = 0;

    mfxExtVPPDoNotUse m_VppDoNotUse;
    std::vector<mfxExtBuffer *> m_VppExtParams;

    mfxExtVPPVideoSignalInfo m_VppVideoSignalInfo;

    CHWDevice *m_hwdev = nullptr;

    mfxU32 m_export_mode = 0;
    mfxI32 m_libvaBackend = 0;

    std::function<void(mfxFrameSurface1 *frame, uint32_t flow_id, uint64_t client_context)> m_deliverDecodedFrameCLBK;

private:
    CStreamDecodingPipeline(const CStreamDecodingPipeline &);
    void operator=(const CStreamDecodingPipeline &);

private:
    std::list<sMemoryBuffer> m_bufferList;
    bool m_busyFlag = false;
};

#endif // __PIPELINE_DECODE_H__
