
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

#include "irp_detection_output.h"

using namespace imif;
using namespace common;
using namespace irp;

static inline std::string &trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

IrpPluginDetectionOutput::IrpPluginDetectionOutput() { m_labels.clear(); }

IrpPluginDetectionOutput::~IrpPluginDetectionOutput() {}

eIrpPluginStatus IrpPluginDetectionOutput::initPlugin(sIrpPluginConfig irpPluginConfig)
{
    m_config = irpPluginConfig;

    if ((m_config.max_number_of_objects < 1) || (m_config.max_number_of_objects > MAX_NUMBER_OF_OBJECTS)) {
        LOG(ERROR) << "The value " << m_config.max_number_of_objects << " for max_num_of_bounding_boxes is illegal.";
        return IRP_PLUGIN_ERROR;
    }

    //load lables from file
    std::ifstream inputFile(irpPluginConfig.labels_file, std::ios::in);
    if (!inputFile.is_open()) {
        LOG(ERROR) << "Can't find labels file: " << irpPluginConfig.labels_file;
        return IRP_PLUGIN_ERROR;
    }

    std::string strLine;
    while (std::getline(inputFile, strLine)) {
        trim(strLine);
        m_labels.push_back(strLine);
    }
    inputFile.close();

    LOG(TRACE) << "plug-in init OK";

    return IRP_PLUGIN_NO_ERROR;
}

struct __attribute__((packed)) IncomingResult {
    float image_id;
    float label;
    float confidence;
    float x_min; // bounding box, normalized
    float y_min; // boundinx box, normalized
    float x_max; // boundinx box, normalized
    float y_max; // boundinx box, normalized
};

eIrpPluginStatus IrpPluginDetectionOutput::postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob,
                                                       size_t blobByteSize, uint32_t image_id,
                                                       std::vector<sInferenceResult> &results)
{
    const size_t num_detections = blobByteSize / sizeof(IncomingResult);

    const float detection_threshold = m_config.accuracy_threshold;
    size_t image_width = frame_info.frame().width();
    size_t image_height = frame_info.frame().height();

    size_t num_detected = 0;

    const float *blob_read_ptr = (float *)pOutputBlob;
    for (size_t i = 0; i < num_detections; ++i, blob_read_ptr += sizeof(IncomingResult) / sizeof(float)) {

        auto detection = *(reinterpret_cast<const IncomingResult *>(blob_read_ptr));
        if (detection.confidence > detection_threshold) {
            LOG(DEBUG) << "Incoming result from network: #" << i << " blobSize=" << blobByteSize
                       << " image_id=" << detection.image_id << " label=" << detection.label
                       << " confidence=" << detection.confidence << " x_min=" << detection.x_min << " x_max=" << detection.x_max
                       << " y_min=" << detection.y_min << " y_max=" << detection.y_max;

            if (detection.image_id != image_id) {
                LOG(DEBUG) << "Skipping because detection.image_id " << detection.image_id << " != image_id " << image_id;
                continue;
            } else {
                LOG(DEBUG) << "Proceed  because detection.image_id " << detection.image_id << " == image_id " << image_id;
            }

            if ((detection.x_max == 0.0) || (detection.y_max == 0.0)) {
                LOG(DEBUG) << "Skipping because max=0";
                continue;
            }

            if (detection.confidence > 1.0) {
                LOG(DEBUG) << "Skipping because confidence>1";
                continue;
            }

            if (detection.x_min < 0.0)
                detection.x_min = 0.0;
            if (detection.y_min < 0.0)
                detection.y_min = 0.0;

            if (num_detected < m_config.max_number_of_objects) {
                sInferenceResult result;
                auto label_id = static_cast<int>(detection.label);
                result.label = (label_id >= 0 && static_cast<size_t>(label_id) < m_labels.size())
                                   ? m_labels[label_id]
                                   : "LABEL_NOT_FOUND_" + std::to_string(label_id);
                result.probability = detection.confidence;
                result.box.x = detection.x_min * image_width;
                result.box.y = detection.y_min * image_height;
                result.box.width = (detection.x_max - detection.x_min) * image_width;
                result.box.height = (detection.y_max - detection.y_min) * image_height;
                results.push_back(result);
                num_detected++;
            } else {
                LOG(DEBUG) << "Skipping detection becuase too many detections";
                // TODO Maybe need to select based on confidence
            }
        }
    }

    return IRP_PLUGIN_NO_ERROR;
}

extern "C" IrpPlugin &get_plugin()
{
    static IrpPluginDetectionOutput plugin;
    return plugin;
}
