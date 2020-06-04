
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

#ifndef _ILB_INFERENCE_OPEN_VINO_H
#define _ILB_INFERENCE_OPEN_VINO_H

/*
    This class implements the InferenceEngine abstract class for Open-Vino framework
 */

#include "ilb_inference.h"
#include "ilb_thread.h"
#include "inference_engine.hpp"
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <extension/ext_list.hpp>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <vector>

using namespace InferenceEngine;

namespace imif {
namespace ilb {

class ConsoleErrorListener : public InferenceEngine::IErrorListener {

    void onError(const char *msg) noexcept override { LOG(INFO) << "Inference Engin Plugin message: " << msg; }
};

inline void printPluginVersion(InferenceEngine::InferenceEnginePluginPtr ptr)
{
    const InferenceEngine::Version *pluginVersion = nullptr;
    ptr->GetVersion(pluginVersion);
    LOG(INFO) << "OpenVino Plugin version: " << pluginVersion;
}

#define ENABLE_CPU_PIN ("YES") //CPU threads pinning for CPU-involved inference ("YES" or "NO")

#define ADD_STATISTICS                                                                                                             \
    for (size_t n = 0lu; n < N; n++) {                                                                                             \
        size_t nC = n * C;                                                                                                         \
        for (size_t c = 0lu; c < C; c++) {                                                                                         \
            m_stat_data->addStatistics(info._name, c, &ptr[(nC + c) * HW], HW);                                                    \
        }                                                                                                                          \
    }

template <class Key> class CaselessEq : public std::binary_function<Key, Key, bool> {
public:
    bool operator()(const Key &a, const Key &b) const noexcept
    {
        return a.size() == b.size() && std::equal(std::begin(a), std::end(a), std::begin(b), [](const char &cha, const char &chb) {
                   return std::tolower(cha) == std::tolower(chb);
               });
    }
};

inline std::size_t getTensorDescWidth(const InferenceEngine::TensorDesc &desc)
{
    const auto &dims = desc.getDims();
    const auto &size = dims.size();
    if (size >= 2) {
        const auto &layout = desc.getLayout();
        switch (layout) {
        case InferenceEngine::Layout::NCHW:
            // fall through
        case InferenceEngine::Layout::NHWC:
            // fall through
        case InferenceEngine::Layout::NCDHW:
            // fall through
        case InferenceEngine::Layout::NDHWC:
            // fall through
        case InferenceEngine::Layout::OIHW:
            // fall through
        case InferenceEngine::Layout::CHW:
            // fall through
        case InferenceEngine::Layout::HW:
            return dims.back();
        default:
            break;
        }
    }
    LOG(ERROR) << "TensorDesc does not have width value";
    return 0;
}

inline std::size_t getTensorDescHeight(const InferenceEngine::TensorDesc &desc)
{
    // Regardless of layout, dimensions are stored in fixed order
    const auto &dims = desc.getDims();
    const auto &size = dims.size();
    if (size >= 2) {
        const auto &layout = desc.getLayout();
        switch (layout) {
        case InferenceEngine::Layout::NCHW:
            // fall through
        case InferenceEngine::Layout::NHWC:
            // fall through
        case InferenceEngine::Layout::NCDHW:
            // fall through
        case InferenceEngine::Layout::NDHWC:
            // fall through
        case InferenceEngine::Layout::OIHW:
            // fall through
        case InferenceEngine::Layout::CHW:
            // fall through
        case InferenceEngine::Layout::HW:
            return dims.at(size - 2);
        default:
            break;
        }
    }
    LOG(ERROR) << "TensorDesc does not have height value";
    return 0;
}

inline std::size_t getTensorDescChannels(const InferenceEngine::TensorDesc &desc)
{
    // Regardless of layout, dimensions are stored in fixed order
    const auto &layout = desc.getLayout();
    switch (layout) {
    case InferenceEngine::Layout::NCHW:
        // fall through
    case InferenceEngine::Layout::NHWC:
        // fall through
    case InferenceEngine::Layout::NCDHW:
        // fall through
    case InferenceEngine::Layout::NDHWC:
        // fall through
    case InferenceEngine::Layout::C:
        // fall through
    case InferenceEngine::Layout::CHW:
        // fall through
    case InferenceEngine::Layout::NC:
        // fall through
    case InferenceEngine::Layout::CN:
        break;
    default:
        LOG(ERROR) << "Tensor does not have channels value";
        return 0;
    }

    const auto &dims = desc.getDims();
    int ret_idx = -1;
    switch (desc.getLayoutByDims(dims)) {
    case InferenceEngine::Layout::NC:
        ret_idx = 1;
        break;
    case InferenceEngine::Layout::C:
        ret_idx = 0;
        break;
    case InferenceEngine::Layout::CHW:
        ret_idx = 0;
        break;
    case InferenceEngine::Layout::NCDHW:
        ret_idx = 1;
        break;
    case InferenceEngine::Layout::NCHW:
        ret_idx = 1;
        break;
    case InferenceEngine::Layout::SCALAR:
        // fall through
    case InferenceEngine::Layout::BLOCKED:
        // fall through
    default:
        LOG(ERROR) << "Tensor does not have channels dimension";
        return 0;
    }
    return dims.at(ret_idx);
}

inline std::size_t getTensorDescBatch(const InferenceEngine::TensorDesc &desc)
{
    const auto &layout = desc.getLayout();
    switch (layout) {
    case InferenceEngine::Layout::NCHW:
        // fall through
    case InferenceEngine::Layout::NHWC:
        // fall through
    case InferenceEngine::Layout::NCDHW:
        // fall through
    case InferenceEngine::Layout::NDHWC:
        // fall through
    case InferenceEngine::Layout::NC:
        // fall through
    case InferenceEngine::Layout::CN:
        break;
    default:
        LOG(ERROR) << "Tensor does not have channels value";
        return 0;
    }

    // Regardless of layout, dimensions are stored in fixed order
    const auto &dims = desc.getDims();
    switch (desc.getLayoutByDims(dims)) {
    case InferenceEngine::Layout::NC:
        // fall through
    case InferenceEngine::Layout::NCHW:
        // fall through
    case InferenceEngine::Layout::NCDHW:
        return dims.at(0);
    case InferenceEngine::Layout::CHW:
        // fall through
    case InferenceEngine::Layout::SCALAR:
        // fall through
    case InferenceEngine::Layout::C:
        // fall through
    case InferenceEngine::Layout::BLOCKED:
        // fall through
    default:
        LOG(ERROR) << "Tensor does not have channels value";
        return 0;
    }
    return 0;
}

typedef struct {
    uint index;
    std::string output_name;
    std::vector<std::string> *p_labels;
} requestData_t;

class OpenVinoInferenceRequest {
    friend class OpenVinoInferenceEngine;

public:
    OpenVinoInferenceRequest(InputsDataMap inputDataMap, OutputsDataMap outputDataMap);
    void pushImageDesc(imif::messages::types::FrameInfo flow) { m_image_descriptors.push_back(flow); }
    imif::messages::types::FrameInfo popImageDesc();
    void allocateRequests(CNNNetwork cnn_network, ExecutableNetwork exe_network);
    void setRequestProperties(std::string modelType);
    void start(const inferenceInputVec &input);
    size_t outputSize() { return m_outputSize; }

private:
    InferenceEngine::InferRequest m_request = InferenceEngine::InferRequest();
    BlobMap m_inputBlob;
    size_t m_outputSize = 0;
    CNNNetwork m_cnn_network;
    InputsDataMap m_networkInputInfo;
    OutputsDataMap m_networkOutputInfo;
    std::vector<imif::messages::types::FrameInfo> m_image_descriptors;
    size_t m_width = 0;
    size_t m_height = 0;
    size_t m_numChannels = 0;
    size_t m_batchSize = 1;
    std::chrono::steady_clock::time_point m_start_timestamp;
    std::string m_modelType = "";
};

struct TensorStatistic {
    TensorStatistic(float *data, size_t count, size_t nbuckets = 1000);
    float getMaxValue() const;
    float getMinValue() const;

protected:
    float _min = 0;
    float _max = 0;
};

class IlbDataStats {
public:
    struct layerInfo {
        std::string _name;
        size_t _batch;
        size_t _channels;
    };

    virtual void addStatistics(const std::string &name, size_t channel, float *data, size_t count) = 0;
    void addStatistics(const std::string &name, size_t channel, short *data, size_t count);
    void addStatistics(const std::string &name, size_t channel, uint8_t *data, size_t count);
    virtual void registerLayer(const std::string &name, size_t batch, size_t channels);
    inline const std::list<layerInfo> &registeredLayers() const { return _registeredLayers; }
    virtual void getDataMinMax(const std::string &name, size_t channel, float &min, float &max, float threshold = 100.f) = 0;
    virtual size_t getNumberChannels(const std::string &name) const = 0;

protected:
    std::list<layerInfo> _registeredLayers;
    std::mutex add_mutex;
};

class IlbSimpleDataStats : public IlbDataStats {
public:
    void addStatistics(const std::string &name, size_t channel, float *data, size_t count);
    void registerLayer(const std::string &name, size_t batch, size_t channels);
    size_t getNumberChannels(const std::string &name) const;
    void getDataMinMax(const std::string &name, size_t channel, float &min, float &max, float threshold = 100.f);

protected:
    struct statsPair {
        float _min = std::numeric_limits<float>::max();
        float _max = std::numeric_limits<float>::min();
    };
    std::unordered_map<std::string, std::unordered_map<size_t, statsPair>> _data;
};

class OpenVinoInferenceEngine : public IlbInferenceEngine {

public:
    OpenVinoInferenceEngine();
    ~OpenVinoInferenceEngine();

    eInferenceEngineStatus addPluginFolder(std::string folderPath);
    eInferenceEngineStatus setDevice(std::string deviceType);
    eInferenceEngineStatus setDevice(uint32_t device_num);
    eInferenceEngineStatus loadNetwork(std::string networkPath, size_t n_threads, size_t batch_size, std::string model_type,
                                       uint32_t num_of_requests, size_t stats_frames, std::string stats_path,
                                       std::string input_layer_precision, bool hetero_dump_graph_dot);
    size_t outputSize() { return m_outputSize; };
    eInferenceEngineStatus setBatchSize(std::size_t size);
    eInferenceEngineStatus runInference(const inferenceInputVec &input);
    eInferenceEngineStatus inferenceWait();
    eInferenceEngineStatus getPerformance(void *output);

    std::string getLabel(uint32_t classificationIndex)
    {
        return (m_labels.size() > classificationIndex ? m_labels[classificationIndex] : "Not found!");
    }

    bool hasPendingRequests();
    int getResult(std::shared_ptr<imif::common::shmem_buff> buff, inferenceResult &result);
    int getNumPendingRequests();
    void unloadNetwork();
    uint getOldestDurationMs();

private:
    std::vector<std::string> m_pluginFolders; //contains a list of plugin folders to search from
    std::string m_device;                     //contains the device to be used
    Core m_ie_core;                           //the inference object that the inference engine will use
    bool m_enablePluginMessages = true;       //indicates whether or not to enable internal plugin messages to stdout
    CNNNetReader m_networkReader;             //CNN network reader object
    CNNNetwork m_network;                     //CNN network object
    InputsDataMap m_networkInputInfo;         //information on the input layer topology respresented as a map<string, smart_ptr>
    OutputsDataMap m_networkOutputInfo;       //information on the output layer topology respresented as a map<string, smart_ptr>
    std::shared_ptr<uint8_t> m_imageData = nullptr; //pointer to the image data
    bool m_isInputLoaded = false;         //used for sanity checking that we don't run inference without loading the input first
    std::vector<Blob::Ptr> m_outputBlobs; //output blob(s)
    uint32_t m_deviceId = 0;              //HW device ID

    size_t m_numInferRequests = 0;              //desired infer request
    size_t m_numOfRunningInferenceRequests = 0; //number of currently running inference requests
    size_t m_batchSize = 1;                     //desired batch size
    size_t m_nThreads = 1;
    size_t m_rgbWidth = 0;
    size_t m_rgbHeight = 0;
    std::string m_network_file_path = "";
    std::string m_model_type = "";
    std::vector<std::string> m_labels; //contains the network's labels
    ExecutableNetwork m_executable_network;

    static eInferenceEngineStatus ReadHeteroAffinity(CNNNetwork &network, std::string device_str, std::string modelBaseName);

    void loadInput(uint8_t *rgb8_image, size_t width, size_t height, BlobMap *blob);

    std::map<uint32_t, InferenceEngine::InferRequest> m_inferRequests;

    std::vector<OpenVinoInferenceRequest> m_freeRequests;
    std::vector<OpenVinoInferenceRequest> m_usedRequests;

    size_t m_outputSize = 0;

    //statistics collection
    std::string m_stats_path = "";
    size_t m_stats_frames = 0;
    size_t m_stats_frame_counter = 0;
    std::shared_ptr<IlbDataStats> m_stat_data = nullptr;
    InferenceEngine::NetworkStatsMap getStatistics(float threshold = 100.f);
    void collectCalibrationStatistic(InferenceEngine::InferRequest &inferRequest);
    void statCollectionRegisterLayers();
    void statCollectionAddOutputLayers();
    void saveIRWithStatistics();
};

} // namespace ilb
} // namespace imif

#endif //of #ifndef _ILB_INFERENCE_OPEN_VINO_H
