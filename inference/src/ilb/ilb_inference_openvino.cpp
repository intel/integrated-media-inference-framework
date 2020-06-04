
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

/*

    This class implements the InferenceEngine abstract class for Open-Vino framework

*/
#include "ilb_inference_openvino.h"
#include "hetero/hetero_plugin_config.hpp"
#include "ie_plugin_config.hpp"
#include "common_broker_thread.h"
#include "common_os_utils.h"
#include "yaml_wrapper.h"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/objdetect/objdetect.hpp"

#include <regex>

using namespace imif;
using namespace common;
using namespace ilb;
using namespace cv;

extern IlbDebug g_ilbDebug;

std::map<InferenceEngine::IInferRequest::Ptr, requestData_t> g_inferenceMap;
std::map<uint32_t, uint32_t> g_results;

//----------------------- static utilities to be used by the open vino class -----------------------

static std::string fileNameNoExt(const std::string &filepath)
{
    auto pos = filepath.rfind('.');
    if (pos == std::string::npos)
        return filepath;
    return filepath.substr(0, pos);
}

static std::string fileBaseName(const std::string &filepath)
{
    auto pos = filepath.rfind('/');
    if ((pos != std::string::npos) && ((pos + 1) < filepath.size())) {
        return filepath.substr(pos + 1, filepath.size());
    }
    return filepath;
}

OpenVinoInferenceEngine::OpenVinoInferenceEngine()
{
    m_device.clear();
    m_model_type.clear();
    m_usedRequests.clear();
    m_inferRequests.clear();
    m_outputBlobs.clear();
    m_labels.clear();
    m_networkOutputInfo.clear();
    m_networkInputInfo.clear();
    m_freeRequests.clear();
    m_pluginFolders.clear();
}

OpenVinoInferenceEngine::~OpenVinoInferenceEngine() {}

//adds a folder to a list of folders that will be used to search for inference engine plugins
eInferenceEngineStatus OpenVinoInferenceEngine::addPluginFolder(std::string folderPath)
{
    LOG(TRACE) << "addPluginFolder " << folderPath;

    m_pluginFolders.push_back(folderPath);

    return INFERENCE_ENGINE_NO_ERROR;
}

//sets which device should use open-vino for this network (e.g. "CPU", "GPU", "FGPA", etc.)
eInferenceEngineStatus OpenVinoInferenceEngine::setDevice(std::string deviceType)
{
    LOG(TRACE) << "setDevice type: " << deviceType;

    //keep local copy. required for inference plugin config
    m_device = deviceType;

    return INFERENCE_ENGINE_NO_ERROR;
}

eInferenceEngineStatus OpenVinoInferenceEngine::setDevice(uint32_t device_num)
{
    LOG(TRACE) << "setDevice number: " << std::to_string(device_num);
    m_deviceId = device_num;
    return INFERENCE_ENGINE_NO_ERROR;
}

std::regex pattern_to_regex(std::string pattern)
{
    // This function translates the patterns supported in the affinity files
    // to C++ regex.

    // Make sure no special characters are carried to the regex by escaping everything.
    std::string s = std::regex_replace(pattern, std::regex("[^A-Za-z0-9%_]"), "\\$&");

    // Translate % to a regex
    s = std::regex_replace(s, std::regex("%"), ".*");

    // The pattern must match all of the destination string
    s = "^" + s + "$";
    LOG(DEBUG) << "pattern_to_regex:  " << pattern << "  --> " << s;
    return std::regex(s);
}

eInferenceEngineStatus OpenVinoInferenceEngine::ReadHeteroAffinity(CNNNetwork &network, const std::string device_str,
                                                                   std::string modelBaseName)
{
    // OpenVino HETERO plugin should be able to split the network's layers between the various
    // participating layers in an adequate manner. However if this fails, there is an option to manually
    // map layers to devices. For example if the model file IR is provided in files model1.xml and model1.bin,
    // create a file called model1_hetero_CPU,GPU.yaml in the same directory.
    // The format of this file is as following:
    //     "pattern" : "affinity"
    //     "pattern" : "affinity"
    //     "pattern" : "affinity"
    // Where `pattern` is a layer name. It can contain the wildcard % which can stand for any number of characters.
    // If multiple patterns match a alyer name, the first pattern match is used.
    // `affinity` is the name of the device for which these layers will be assigned. For example: "CPU".
    // The file must apply affinity for every layer in the model.
    if (device_str.find("HETERO:") != 0)
        return INFERENCE_ENGINE_NO_ERROR;
    auto devices_str = device_str.substr(7, std::string::npos);

    std::vector<std::string> device_names;
    const auto delim = std::regex(",");
    std::copy(std::sregex_token_iterator(devices_str.begin(), devices_str.end(), delim, -1), std::sregex_token_iterator(),
              std::back_insert_iterator<std::vector<std::string>>(device_names));
    std::sort(device_names.begin(), device_names.end());
    do {
        std::string filename;
        for (const auto &devname : device_names) {
            if (!(filename.empty()))
                filename += ",";
            filename += devname;
        }
        filename = modelBaseName + "_hetero_" + filename + ".yaml";

        std::ifstream fin(filename.c_str());
        if (!fin)
            continue;
        fin.close();

        LOG(INFO) << "Loading affinity from file " << filename;
        auto document = imif_yaml::yaml_builder::parse_file(filename);
        if (!document || !document.is_map()) {
            LOG(ERROR) << "Incorrect format in file " << filename;
            return INFERENCE_ENGINE_ERROR;
        }

        // Load the patterns from the yaml file and convert to a list of regular expressions
        std::vector<std::pair<std::regex, std::string>> rules;
        for (auto it = document.map_begin(); it != document.map_end(); ++it) {
            rules.emplace_back(std::make_pair(pattern_to_regex(it->first), it->second->scalar()));
        }

        // Apply the rules to find affinity for each layer
        for (auto &layer : network) {
            for (const auto &rule : rules) {
                if (std::regex_search(layer->name, rule.first)) {
                    layer->affinity = rule.second;
                    LOG(DEBUG) << "Setting affinity=" << layer->affinity << " for LayerName=" << layer->name;
                    break;
                }
            }
        }

        return INFERENCE_ENGINE_NO_ERROR;
    } while (next_permutation(device_names.begin(), device_names.end()));

    return INFERENCE_ENGINE_NO_ERROR;
}

//loads the network from the xml/bin files
eInferenceEngineStatus OpenVinoInferenceEngine::loadNetwork(std::string networkPath, size_t n_threads, size_t batch_size,
                                                            std::string model_type, uint32_t num_of_requests, size_t stats_frames,
                                                            std::string stats_path, std::string input_layer_precision,
                                                            bool hetero_dump_graph_dot)
{
    m_model_type = model_type;
    m_network_file_path = networkPath;
    m_stats_frames = stats_frames;
    m_stats_path = stats_path;
    m_nThreads = n_threads;
    if (m_stats_path.back() != '/')
        m_stats_path += "/";

    //if CPU plugin was chosen, load its appropriate extensions
    if (m_device.find("CPU") != std::string::npos) {
        LOG(INFO) << "Adding OpenVino CPU extensions";
        m_ie_core.AddExtension(std::make_shared<Extensions::Cpu::CpuExtensions>(), "CPU");
    }

    if (hetero_dump_graph_dot) {
        LOG(INFO) << "Enabling dumping hetero affinity maps. Look for the files hetero_*.dot";
        m_ie_core.SetConfig(
            {{InferenceEngine::HeteroConfigParams::KEY_HETERO_DUMP_GRAPH_DOT, InferenceEngine::PluginConfigParams::YES}}, "HETERO");
    }

    std::string devices = m_device;
    size_t pos = devices.npos;
    while (!devices.empty()) {
        pos = devices.find(":");
        std::string substring;
        if (pos != devices.npos) {
            substring = devices.substr(0, pos);
            if (substring != "HETERO") {
                LOG(ERROR) << "Unexpected devices string " << m_device;
                return INFERENCE_ENGINE_NOT_SUPPORTED;
            }
            devices.erase(0, pos + 1);
        }
        pos = 0;
        pos = devices.find(",");
        if (pos == devices.npos)
            pos = devices.size();
        substring = devices.substr(0, pos);
        if (substring != "CPU" && substring != "GPU" && substring != "VPU" && substring != "MYRIAD") {
            std::map<std::string, std::string> plugin_config;
            plugin_config["deviceNum"] = std::to_string(m_deviceId);

            m_ie_core.SetConfig(plugin_config, substring);
        }
        devices.erase(0, pos + 1);
    }

    // Load network model (xml)
    m_networkReader.ReadNetwork(networkPath);

    // Load weights (bin)
    m_networkReader.ReadWeights(fileNameNoExt(networkPath) + ".bin");

    // get the network object from the network reader
    m_network = m_networkReader.getNetwork();

    //Read the Hetero affinity mapping, if a relevant file exists
    ReadHeteroAffinity(m_network, m_device, fileNameNoExt(networkPath));

    if (m_stats_frames > 0) {
        statCollectionAddOutputLayers(); ///must be done before blobs are allocated and inputs/outputs info are obtained
    }

    //load the info topology from this network. make sure input layer size is 1
    m_networkInputInfo = m_network.getInputsInfo();
    m_networkOutputInfo = m_network.getOutputsInfo();
    if (m_networkInputInfo.size() != 1) {
        LOG(ERROR) << "OpenVinoInferenceEngine::loadNetwork: Input size = " << m_networkInputInfo.size() << " is not supported";
        return INFERENCE_ENGINE_NOT_SUPPORTED;
    }

    for (auto &input_layer : m_networkInputInfo) {
        LOG(INFO) << "Input layers precision: " << input_layer.second->getPrecision();
    }

    //set batch size
    setBatchSize(batch_size);

    // set the input precision to uint8
    if (input_layer_precision == "uint8") {
        m_networkInputInfo.begin()->second->setPrecision(Precision::U8);
    }

    //allocate input blobs
    for (uint32_t i = 0; i < num_of_requests; i++) {
        OpenVinoInferenceRequest request(m_networkInputInfo, m_networkOutputInfo);
        m_freeRequests.push_back(request);
    }

    //config plugin
    std::map<std::string, std::string> config;
    config[PluginConfigParams::KEY_PERF_COUNT] = PluginConfigParams::NO;
    if (m_device.find("CPU") != std::string::npos) { // CPU supports few special performance-oriented keys

        // limit threading for CPU portion of inference
        config[PluginConfigParams::KEY_CPU_THREADS_NUM] = std::to_string(n_threads);
        // pin threads for CPU portion of inference
        config[PluginConfigParams::KEY_CPU_BIND_THREAD] = ENABLE_CPU_PIN;
        // for pure CPU execution, more throughput-oriented execution via streams
        config[PluginConfigParams::KEY_CPU_THROUGHPUT_STREAMS] = PluginConfigParams::CPU_THROUGHPUT_NUMA;
    }

    //load plugin to network --> this should be done after allocating the inference requests' input blobs
    m_executable_network = m_ie_core.LoadNetwork(m_network, m_device);

    //allocate output blobs and requests. this can only be done after we have the executable network, which in turn can only be done after we allocate the input blobs
    for (uint32_t i = 0; i < num_of_requests; i++) {
        m_freeRequests[i].allocateRequests(m_network, m_executable_network);
        m_freeRequests[i].setRequestProperties(m_model_type);
    }

    m_outputSize = m_freeRequests[0].outputSize();

    if (m_stats_frames > 0) {
        statCollectionRegisterLayers(); ///must be done after blobs are allocated
    }

    LOG(INFO) << "Successfully loaded network: n_threads=" << n_threads << " stats_frames=" << m_stats_frames
              << " m_outputSize=" << m_outputSize;

    return INFERENCE_ENGINE_NO_ERROR;
}

//sets the inference batch fize
eInferenceEngineStatus OpenVinoInferenceEngine::setBatchSize(std::size_t size)
{
    m_network.setBatchSize(size);
    m_batchSize = size;
    LOG(TRACE) << "setBatchSize: " << std::to_string(m_network.getBatchSize());
    return INFERENCE_ENGINE_NO_ERROR;
}

//wait for the async inference processes to finish processing
eInferenceEngineStatus OpenVinoInferenceEngine::inferenceWait()
{
    if (m_numOfRunningInferenceRequests == 0) {
        LOG(INFO) << "OpenVinoInferenceEngine::inferenceWait: No pending inference requests";
        return INFERENCE_ENGINE_NO_ERROR;
    }

    LOG(INFO) << "OpenVinoInferenceEngine::inferenceWait: Waiting for inference requests to finish...";
    uint32_t infer_idx = 0;
    while (m_numOfRunningInferenceRequests) {
        m_inferRequests[infer_idx++].Wait(InferenceEngine::IInferRequest::WaitMode::RESULT_READY);
        m_numOfRunningInferenceRequests--;
    }
    return INFERENCE_ENGINE_NO_ERROR;
}

//prints out various performance counters
eInferenceEngineStatus OpenVinoInferenceEngine::getPerformance(void *output) { return INFERENCE_ENGINE_NO_ERROR; }

int OpenVinoInferenceEngine::getNumPendingRequests() { return m_usedRequests.size(); }

bool OpenVinoInferenceEngine::hasPendingRequests() { return (m_usedRequests.size() != 0); }

uint OpenVinoInferenceEngine::getOldestDurationMs()
{

    auto now_ms = std::chrono::steady_clock::now();
    uint oldest = 0;

    if (m_usedRequests.size() > 0) {
        for (auto &request : m_usedRequests) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_ms - request.m_start_timestamp).count();
            if (duration > oldest) {
                oldest = duration;
            }
        }
    }
    return oldest;
}

int OpenVinoInferenceEngine::getResult(std::shared_ptr<imif::common::shmem_buff> buff, inferenceResult &result)
{
    static int total_infs = 0;
    if (!buff) {
        LOG(ERROR) << "buff is null!";
        return -1;
    }
    uint8_t *output_ptr = (uint8_t *)buff->ptr();

    std::vector<OpenVinoInferenceRequest>::iterator it = m_usedRequests.begin();
    while (it != m_usedRequests.end()) {

        InferenceEngine::StatusCode status = it->m_request.Wait(InferenceEngine::IInferRequest::WaitMode::STATUS_ONLY);

        if (status == InferenceEngine::StatusCode::OK) {

            OpenVinoInferenceRequest infer_req = std::move(*it);

            //wait for the results
            infer_req.m_request.Wait(InferenceEngine::IInferRequest::WaitMode::RESULT_READY);

            auto now_ms = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_ms - it->m_start_timestamp).count();
            LOG(DEBUG) << "###inference finished. duration[ms]=" << duration << "; total inferences: " << total_infs++
                       << "; output size:" << m_outputSize;

            //collect statistics, if enabled
            if (m_stats_frames > 0) {
                collectCalibrationStatistic(infer_req.m_request);
                m_stats_frame_counter += m_batchSize;
                LOG(DEBUG) << "Collecting stats for frame " << m_stats_frame_counter << " out of " << m_stats_frames;
                if (m_stats_frame_counter >= m_stats_frames) {
                    //stop statistics collection and save the result
                    saveIRWithStatistics();
                    m_stats_frames = 0;
                    LOG(INFO) << "Finished collecting statistics... ending inference operation";
                    std::cout << "\n******\nFinished collecting statistics... ending inference operation\n******\n";
                    exit(0);
                }
            } else { //prepare for imif post processing

                //copy output blobs to shared memory
                size_t blob_offset = 0;
                for (auto iter = m_networkOutputInfo.begin(); iter != m_networkOutputInfo.end(); iter++) {
                    std::string output_layer_name = iter->first;
                    CNNLayerPtr layer = infer_req.m_cnn_network.getLayerByName(output_layer_name.c_str());
                    if (CaselessEq<std::string>()(layer->type, "Const")) {
                        continue;
                    } else {
                        Blob::Ptr outputBlob = infer_req.m_request.GetBlob(output_layer_name);
                        size_t layer_buffer_size = infer_req.m_request.GetBlob(output_layer_name)->byteSize();
                        uint8_t *ptr = output_ptr + blob_offset;

                        std::copy_n((uint8_t *)outputBlob->buffer(), layer_buffer_size, ptr);
                        blob_offset += layer_buffer_size;
                    }
                }
            }

            //copy frame info for all outputs
            size_t idx = 0;
            do {
                auto image_desc = infer_req.popImageDesc();
                auto efr = result.add_efr();
                efr->mutable_frame_info()->CopyFrom(image_desc);
                if (!image_desc.skip_frame() && !image_desc.frame_empty()) {
                    idx++;
                }
            } while (idx < m_batchSize);

            result.mutable_buff()->CopyFrom(*buff);

            m_freeRequests.push_back(infer_req);
            it = m_usedRequests.erase(it);

            return 1;
        } else {
            it++;
        }
    }

    return 0;
}

eInferenceEngineStatus OpenVinoInferenceEngine::runInference(const inferenceInputVec &input)
{

    static int debug_print_backpressure = 0;
    if (!input.size()) {
        LOG(ERROR) << "input vector is empty!";
        return INFERENCE_ENGINE_ERROR;
    }

    if (m_freeRequests.size() == 0) {
        if (!debug_print_backpressure)
            LOG(WARNING) << "No available inference requests";

        debug_print_backpressure = (debug_print_backpressure + 1) % 10000;
        return INFERENCE_ENGINE_BUSY;
    }

    OpenVinoInferenceRequest infer_req = std::move(m_freeRequests.front());
    m_freeRequests.erase(m_freeRequests.begin());
    infer_req.start(input);
    m_usedRequests.push_back(infer_req);

    return INFERENCE_ENGINE_NO_ERROR;
}

OpenVinoInferenceRequest::OpenVinoInferenceRequest(InputsDataMap inputDataMap, OutputsDataMap outputDataMap)
{
    //----------get dimensions----------------------------
    auto inputInfoItem = *inputDataMap.begin();
    auto dims = inputInfoItem.second->getTensorDesc().getDims();
    m_numChannels = dims[1];
    m_width = dims[2];
    m_height = dims[3];

    m_networkInputInfo = inputDataMap;
    m_networkOutputInfo = outputDataMap;

    m_image_descriptors.clear();
    m_inputBlob.clear();
    m_start_timestamp = std::chrono::steady_clock::now();
}

void OpenVinoInferenceRequest::setRequestProperties(std::string modelType) { m_modelType = modelType; }

imif::messages::types::FrameInfo OpenVinoInferenceRequest::popImageDesc()
{
    if (m_image_descriptors.empty()) {
        LOG(ERROR) << "m_image_descriptors is empty!";
        return imif::messages::types::FrameInfo();
    }
    auto elem = m_image_descriptors.front();
    m_image_descriptors.erase(m_image_descriptors.begin());
    return elem;
}

void OpenVinoInferenceRequest::allocateRequests(CNNNetwork cnn_network, ExecutableNetwork exe_network)
{

    m_cnn_network = cnn_network;
    m_batchSize = cnn_network.getBatchSize();

    //create infer request
    m_request = exe_network.CreateInferRequest();

    OutputsDataMap::iterator iter;
    m_outputSize = 0;
    for (iter = m_networkOutputInfo.begin(); iter != m_networkOutputInfo.end(); iter++) {
        std::string output_layer_name = iter->first;

        CNNLayerPtr layer = cnn_network.getLayerByName(output_layer_name.c_str());
        if (CaselessEq<std::string>()(layer->type, "Const")) {
            LOG(DEBUG) << "Ignoring layer " << output_layer_name;
        } else {
            m_outputSize += m_request.GetBlob(iter->first)->byteSize();
            LOG(DEBUG) << "Layer " << output_layer_name << " size=" << m_request.GetBlob(iter->first)->byteSize()
                       << "; total size=" << m_outputSize;
        }
    }
}

void OpenVinoInferenceRequest::start(const inferenceInputVec &input)
{

    for (auto &item : m_networkInputInfo) {

        const size_t plane_size = m_width * m_height;

        auto blob = m_request.GetBlob(item.first);
        auto blobSize = blob->size();
        auto lockedBlob = blob->buffer();
        Precision precision = item.second->getPrecision();

        LOG(DEBUG) << "Request::start loading input with size " << plane_size << " and channels=" << m_numChannels
                   << " and batch size=" << m_batchSize << " input size in bytes:" << blobSize << "; precision=" << precision;

        size_t total_inferred_frames = 0;

        for (size_t image_id = 0; image_id < m_batchSize; ++image_id) {
            auto frame_info = std::get<0>(input[image_id]);
            auto buff = std::get<1>(input[image_id]);
            bool skip_frame = frame_info.skip_frame() || frame_info.frame_empty();
            size_t src_width = frame_info.frame().width();
            size_t src_height = frame_info.frame().height();

            frame_info.mutable_frame()->set_height(m_height);
            frame_info.mutable_frame()->set_width(m_width);

            pushImageDesc(frame_info);

            if (skip_frame) {
                LOG(DEBUG) << "Skipping frame " << (image_id + 1) << " out of total " << input.size() << " frames in the queue";
                continue;
            }

            uint8_t *src_image_buffer = (uint8_t *)buff->ptr();

            std::string frame_format = frame_info.frame().format();
            float height_factor;
            int incoming_pixel_format;
            int rgb_conversion;

            if (frame_format == "nv12") {
                height_factor = 1.5;
                incoming_pixel_format = CV_8UC1;
                rgb_conversion = CV_YUV2RGB_NV12;
            } else if (frame_format == "rgba" || frame_format == "rgb4") {
                height_factor = 1.0;
                incoming_pixel_format = CV_8UC4;
                rgb_conversion = CV_RGBA2RGB;
            } else if (frame_format == "rgb") {
                height_factor = 1.0;
                incoming_pixel_format = CV_8UC3;
                rgb_conversion = -1;
            } else {
                LOG(ERROR) << "ILB unsupported frame type: " << frame_format;
                continue;
            }

            Mat src_image = Mat(src_height * height_factor, src_width, incoming_pixel_format, src_image_buffer);
            Mat scaled_image;

            if (src_width == m_width && src_height == m_height) {
                LOG(DEBUG) << "No scaling needed.";
                scaled_image = src_image;
            } else {
                LOG(DEBUG) << "Scaling from " << src_width << "x" << src_height << " to " << m_width << "x" << m_height;
                scaled_image = Mat(m_height * height_factor, m_width, incoming_pixel_format);
                cv::resize(src_image, scaled_image, scaled_image.size());
            }

            Mat scaled_image_rgb;
            //convert image to RGB
            if (rgb_conversion != -1) {
                LOG(DEBUG) << "Converting to RGB";
                scaled_image_rgb = Mat(m_height, m_width, CV_8UC3);
                cv::cvtColor(scaled_image, scaled_image_rgb, rgb_conversion);
            } else {
                scaled_image_rgb = scaled_image;
            }

            //if debug was enabled, this will append the rgb frame to a file
            g_ilbDebug.ilbWriteToFile(scaled_image_rgb.ptr<uint8_t>(0), m_width * m_height * 3);

            if (precision == Precision::FP32 /*fp32 input */) {
                auto input_buffer = lockedBlob.as<PrecisionTrait<Precision::FP32>::value_type *>();
                float *pDestImage = reinterpret_cast<float *>(input_buffer);
                //convert to floating point 32 bit
                Mat fp32_image = Mat(m_height, m_width, CV_32FC3);
                scaled_image_rgb.convertTo(fp32_image, CV_32FC3);

                auto num_channels = (m_modelType == "bhw_grayscale") ? 1 : 3;

                Mat channel[num_channels];

                for (auto ch = 0; ch < num_channels; ch++) {
                    channel[ch] =
                        Mat(m_height, m_width, CV_32FC1, &pDestImage[(total_inferred_frames * plane_size * 3) + ch * plane_size]);
                }

                if (m_modelType == "bchw_bgr") {
                    // format the image into BGR
                    cv::extractChannel(fp32_image, channel[0], 2); // B
                    cv::extractChannel(fp32_image, channel[1], 1); // G
                    cv::extractChannel(fp32_image, channel[2], 0); // R
                } else if (m_modelType == "bchw_rgb") {
                    // format the image into BGR
                    cv::extractChannel(fp32_image, channel[0], 0); // R
                    cv::extractChannel(fp32_image, channel[1], 1); // G
                    cv::extractChannel(fp32_image, channel[2], 2); // B
                } else if (m_modelType == "bhw_grayscale") {
                    // format the image into grayscale
                    cv::cvtColor(fp32_image, channel[0], COLOR_RGB2GRAY);
                } else {
                    //split the image into  rgb channel and rescale as needed
                    cv::extractChannel(fp32_image, channel[0], 0); // R
                    cv::extractChannel(fp32_image, channel[1], 1); // G
                    cv::extractChannel(fp32_image, channel[2], 2); // B

                    channel[0] = ((channel[0] / 255.0) - 0.485) / 0.229;
                    channel[1] = ((channel[1] / 255.0) - 0.456) / 0.224;
                    channel[2] = ((channel[2] / 255.0) - 0.406) / 0.225;
                }
            } else {
                if (m_modelType == "bchw_bgr") {
                    LOG(ERROR) << "Not implemented: m_modelType==" << m_modelType;
                } else if (m_modelType == "bchw_rgb") {
                    LOG(ERROR) << "Not implemented: m_modelType==" << m_modelType;
                } else if (m_modelType == "bhw_grayscale") {
                    LOG(ERROR) << "Not implemented: m_modelType==" << m_modelType;
                }
                auto input_buffer = lockedBlob.as<PrecisionTrait<Precision::U8>::value_type *>();
                Mat rgbchannel[3];
                rgbchannel[2] =
                    Mat(m_height, m_width, CV_8UC1, &input_buffer[total_inferred_frames * plane_size * 3 + 0 * plane_size]);
                rgbchannel[1] =
                    Mat(m_height, m_width, CV_8UC1, &input_buffer[total_inferred_frames * plane_size * 3 + 1 * plane_size]);
                rgbchannel[0] =
                    Mat(m_height, m_width, CV_8UC1, &input_buffer[total_inferred_frames * plane_size * 3 + 2 * plane_size]);

                cv::extractChannel(scaled_image_rgb, rgbchannel[2], 0);
                cv::extractChannel(scaled_image_rgb, rgbchannel[1], 1);
                cv::extractChannel(scaled_image_rgb, rgbchannel[0], 2);
            }

            if (++total_inferred_frames == m_batchSize) {
                LOG(DEBUG) << "Submitted " << total_inferred_frames << " frames to Open-Vino";
                break;
            }
        }
    }

    m_request.StartAsync();
    m_start_timestamp = std::chrono::steady_clock::now();
}

void OpenVinoInferenceEngine::unloadNetwork() {}

void OpenVinoInferenceEngine::saveIRWithStatistics()
{
    for (auto &layer : m_network) {
        if (layer->precision == Precision::FP32 &&
            (CaselessEq<std::string>()(layer->type, "convolution") || CaselessEq<std::string>()(layer->type, "fullyconnected")))
            layer->params["quantization_level"] = "I8";
    }

    ICNNNetworkStats *pstats = nullptr;
    StatusCode status = ((ICNNNetwork &)m_network).getStats(&pstats, nullptr);
    if (status == StatusCode::OK && pstats) {
        auto statistics = getStatistics();
        pstats->setNodesStats(statistics);
    }

    if (!os_utils::make_dir(m_stats_path)) {
        LOG(ERROR) << "can't create stats_path: " << m_stats_path;
    } else {
        std::string output_path = m_stats_path + fileBaseName(m_network_file_path);
        output_path = fileNameNoExt(output_path) + "_stats";
        LOG(INFO) << "Write network with statistics to " << output_path << ".(xml|bin) IR file";
        m_network.serialize(output_path + ".xml", output_path + ".bin");
    }
}

void OpenVinoInferenceEngine::statCollectionAddOutputLayers()
{
    //add output layers
    for (auto &layer : m_network) {
        const std::string &layerType = layer->type;
        if (!CaselessEq<std::string>()(layerType, "const") && !CaselessEq<std::string>()(layerType, "split") &&
            !CaselessEq<std::string>()(layerType, "input")) {
            m_network.addOutput(layer->name);
        } else {
        }
    }
}

void OpenVinoInferenceEngine::statCollectionRegisterLayers()
{
    m_stat_data = std::make_shared<IlbSimpleDataStats>(); //instantiate a simple data statistics object
    m_stats_frame_counter = 0;

    for (auto &info : m_networkInputInfo) {
        const auto &outBlobDesc = m_freeRequests[0].m_request.GetBlob(info.first)->getTensorDesc();
        if ((outBlobDesc.getLayout() != Layout::NCHW) && (outBlobDesc.getLayout() != Layout::NC) &&
            (outBlobDesc.getLayout() != Layout::C) && (outBlobDesc.getLayout() != Layout::NCDHW)) {
            continue;
        } else {
            m_stat_data->registerLayer(info.first, getTensorDescBatch(outBlobDesc), getTensorDescChannels(outBlobDesc));
        }
    }
    for (auto &info : m_networkOutputInfo) {
        const auto &outBlobDesc = m_freeRequests[0].m_request.GetBlob(info.first)->getTensorDesc();
        if ((outBlobDesc.getLayout() != Layout::NCHW) && (outBlobDesc.getLayout() != Layout::NC) &&
            (outBlobDesc.getLayout() != Layout::C) && (outBlobDesc.getLayout() != Layout::NCDHW)) {
            continue;
        } else {
            m_stat_data->registerLayer(info.first, getTensorDescBatch(outBlobDesc), getTensorDescChannels(outBlobDesc));
        }
    }
}

InferenceEngine::NetworkStatsMap OpenVinoInferenceEngine::getStatistics(float threshold)
{
    InferenceEngine::NetworkStatsMap netNodesStats;
    // go over all outputs and get aggregated statistics
    for (auto &outName : m_stat_data->registeredLayers()) {
        NetworkNodeStatsPtr nodeStats;
        size_t channels = outName._channels;
        if (netNodesStats.find(outName._name) == netNodesStats.end()) {
            nodeStats = NetworkNodeStatsPtr(new NetworkNodeStats(channels));

            netNodesStats[outName._name] = nodeStats;
        } else {
            nodeStats = netNodesStats[outName._name];
        }
        for (size_t c = 0; c < channels; c++) {
            m_stat_data->getDataMinMax(outName._name, c, nodeStats->_minOutputs[c], nodeStats->_maxOutputs[c], threshold);
        }
    }
    return netNodesStats;
}

void OpenVinoInferenceEngine::collectCalibrationStatistic(InferenceEngine::InferRequest &inferRequest)
{
    for (auto &info : m_stat_data->registeredLayers()) {
        auto outBlob = inferRequest.GetBlob(info._name);
        const auto &outBlobDesc = outBlob->getTensorDesc();
        const size_t N = info._batch;
        const size_t C = info._channels;

        size_t HW = 1lu;
        if (outBlobDesc.getLayout() == Layout::NCHW)
            HW = getTensorDescWidth(outBlobDesc) * getTensorDescHeight(outBlobDesc);
        if (outBlobDesc.getPrecision() == Precision::FP32) {
            float *ptr = outBlob->buffer().as<float *>();
            ADD_STATISTICS
        } else if (outBlobDesc.getPrecision() == Precision::FP16) {
            short *ptr = outBlob->buffer().as<short *>();
            ADD_STATISTICS
        } else if (outBlobDesc.getPrecision() == Precision::U8) {
            uint8_t *ptr = outBlob->buffer().as<uint8_t *>();
            ADD_STATISTICS
        } else {
            throw std::logic_error(std::string("Unsupported precision: ") + outBlobDesc.getPrecision().name());
        }
    }
}

//----- dataStats -----//
void IlbDataStats::registerLayer(const std::string &name, size_t batch, size_t channels)
{
    _registeredLayers.push_back({name, batch, channels});
}

void IlbDataStats::addStatistics(const std::string &name, size_t channel, uint8_t *data, size_t count)
{
    float *dst = new float[count];
    for (size_t i = 0lu; i < count; i++) {
        dst[i] = static_cast<float>(data[i]);
    }
    addStatistics(name, channel, dst, count);
    delete[] dst;
}

void IlbDataStats::addStatistics(const std::string &name, size_t channel, short *data, size_t count)
{
    float *dst = new float[count];
    for (size_t i = 0lu; i < count; i++) {
        dst[i] = static_cast<float>(data[i]);
    }
    addStatistics(name, channel, dst, count);
    delete[] dst;
}

//----- simpleDataStats -----//
void IlbSimpleDataStats::registerLayer(const std::string &name, size_t batch, size_t channels)
{
    IlbDataStats::registerLayer(name, batch, channels);
    _data[name];
}

size_t IlbSimpleDataStats::getNumberChannels(const std::string &name) const
{
    auto it = _data.find(name);
    if (it != _data.end()) {
        return it->second.size();
    }
    return 0lu;
}

void IlbSimpleDataStats::addStatistics(const std::string &name, size_t channel, float *data, size_t count)
{
    auto &byChannel = _data[name][channel];
    // TODO: Investigate synchronization of _data usage
    // add_mutex.lock();
    for (size_t i = 0lu; i < count; i++) {
        if (byChannel._min > data[i]) {
            byChannel._min = data[i];
        }

        if (byChannel._max < data[i]) {
            byChannel._max = data[i];
        }
    }
    // add_mutex.unlock();
}

void IlbSimpleDataStats::getDataMinMax(const std::string &name, size_t channel, float &min, float &max, float threshold)
{
    auto it = _data.find(name);
    if (it != _data.end()) {
        min = it->second[channel]._min;
        max = it->second[channel]._max;
    } else {
        min = max = 0.f;
    }
}

//----- TensorStatistic -----//
TensorStatistic::TensorStatistic(float *data, size_t count, size_t nbuckets)
{
    _min = std::numeric_limits<float>::max();
    _max = std::numeric_limits<float>::min();
    for (size_t i = 0; i < count; i++) {
        float val = static_cast<float>(data[i]);
        if (_min > val) {
            _min = val;
        }

        if (_max < val) {
            _max = val;
        }
    }

    if (_min == _max) {
        return;
    }
}

float TensorStatistic::getMaxValue() const { return _max; }

float TensorStatistic::getMinValue() const { return _min; }
