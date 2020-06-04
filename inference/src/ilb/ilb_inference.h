
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

#ifndef _ILB_INFERENCE_H
#define _ILB_INFERENCE_H
#include "easylogging++.h"
#include "common_mem_manager.h"
#include <chrono>
#include <memory>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include <messages/proto/inference.pb.h>
#include <messages/proto/types.pb.h>

#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/imgproc/types_c.h"
#include "opencv2/objdetect/objdetect.hpp"

#define NUM_OF_INFERENCE_RESOURCES (30)

/*
        Abstract class of a generic inference engine (for example, Open-Vino, etc.) to be used
        within IMIF-ILB.
*/

enum eInferenceEngineStatus {
    INFERENCE_ENGINE_NO_ERROR = 0x0,
    INFERENCE_ENGINE_ERROR = 0x1,
    INFERENCE_ENGINE_NOT_SUPPORTED = 0x2,
    INFERENCE_ENGINE_BUSY = 0x3,
    INFERENCE_ENGINE_NOT_ENOUGH_FRAMES = 0x4
};

enum ePrecision {
    PRECISION_U8,   //8 bit unsigned fixed point
    PRECISION_I8,   //8 bit signed fixed pointer
    PRECISION_U16,  //16 bit unsigned fixed point
    PRECISION_I16,  //16 bit signed fixed pointer
    PRECISION_U32,  //32 bit unsigned fixed point
    PRECISION_I32,  //32 bit signed fixed pointer
    PRECISION_FP16, //16 bit floating point
    PRECISION_FP32, //32 bit floating point
    PRECISION_BIN   //1 bit (binary)
};

enum eLayout {
    LAYOUT_ANY,
    LAYOUT_NCHW,
    LAYOUT_NHWC,
    LAYOUT_OIHW,
    LAYOUT_C,
    LAYOUT_CHW,
    LAYOUT_HW,
    LAYOUT_NC,
    LAYOUT_CN,
    LAYOUT_NCDHW
};

#define INF_ENGINE_CHECK_STATUS(x)                                                                                                 \
    {                                                                                                                              \
        eInferenceEngineStatus status;                                                                                             \
        status = x;                                                                                                                \
        if (status != INFERENCE_ENGINE_NO_ERROR) {                                                                                 \
            LOG(ERROR) << "INFERENCE ERROR in function " << __FUNCTION__ << " on line " << __LINE__ << " with status: " << status  \
                       << ". Aborting...\n";                                                                                       \
            exit(status);                                                                                                          \
        }                                                                                                                          \
    }

namespace imif {
namespace ilb {

typedef std::pair<imif::messages::types::FrameInfo, std::shared_ptr<imif::common::shmem_buff>> inferenceInput;
typedef std::vector<inferenceInput> inferenceInputVec;
typedef imif::messages::inference::RawResult inferenceResult;

class IlbInferenceEngine {

public:
    IlbInferenceEngine() {}
    virtual ~IlbInferenceEngine() {}

    //adds a folder to a vector of folder-paths in which the inference engine shall search for plugins
    virtual eInferenceEngineStatus addPluginFolder(std::string folderPath) = 0;

    //sets the desired device to use for inference, with string parameter (for example, "CPU", "GPU", "FPGA", etc.)
    virtual eInferenceEngineStatus setDevice(std::string deviceType) = 0;

    //sets the desired device to use for inference, with device number parameter
    virtual eInferenceEngineStatus setDevice(uint32_t device_num) = 0;

    //loads the network into the inference engine
    virtual eInferenceEngineStatus loadNetwork(std::string networkPath, size_t n_threads, size_t batch_size, std::string model_type,
                                               uint32_t num_of_requests, size_t stats_frames, std::string stats_path,
                                               std::string input_layer_precision, bool hetero_dump_graph_dot) = 0;

    //get maximun output size
    virtual size_t outputSize() = 0;

    //sets the batch size
    virtual eInferenceEngineStatus setBatchSize(std::size_t size) = 0;

    //does inference (either sync or asynch)
    virtual eInferenceEngineStatus runInference(const inferenceInputVec &input) = 0;

    //wait for the asynchronous inference requests to complete
    virtual eInferenceEngineStatus inferenceWait() = 0;

    //get performance / stats
    virtual eInferenceEngineStatus getPerformance(void *output) = 0;

    //gets the starting timestamp of the oldest inference request that was submitted
    virtual uint getOldestDurationMs() = 0;

    //gets the label per class
    virtual std::string getLabel(uint32_t classificationIndex) = 0;

    //checks if there are pending inference requests that haven't been completed yet
    virtual bool hasPendingRequests() = 0;

    //gets the number of pending requests
    virtual int getNumPendingRequests() = 0;

    //checks if there are inference results waiting
    virtual int getResult(std::shared_ptr<imif::common::shmem_buff> buff, inferenceResult &result) = 0;

    //unloads the network from the inference engine in an orderly way
    virtual void unloadNetwork() = 0;
};

} // namespace ilb
} // namespace imif

#endif //of #ifndef _ILB_INFERENCE_H
