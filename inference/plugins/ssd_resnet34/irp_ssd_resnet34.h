
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

#ifndef _IRP_PLUGIN_SSDRESNET34_H
#define _IRP_PLUGIN_SSDRESNET34_H

#include "irp_plugin.h"

namespace imif {
namespace irp {

typedef struct {
    cv::Rect_<float> bounding_box;
    float detection_score;
    size_t category_id;
    uint32_t label; //index of label
} DetectionResult;

class IrpPluginSsdResnet34 : public IrpPlugin {

public:
    IrpPluginSsdResnet34();
    ~IrpPluginSsdResnet34();

    //Initializes the plugin
    eIrpPluginStatus initPlugin(sIrpPluginConfig irpPluginConfig);

    //Initializes the plugin
    eIrpPluginStatus postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob, size_t blobByteSize,
                                 uint32_t image_id, std::vector<sInferenceResult> &results);

private:
    std::vector<std::string> m_labels;
    std::vector<cv::Rect_<float>> m_default_boxes; //for ssd

    double *softmax(float *src, size_t nvars, size_t n);

    template <typename __primitive_t>
    void scaleBack(std::vector<cv::Rect_<__primitive_t>> &regressed_boxes, const __primitive_t *predicted_boxes,
                   const std::vector<cv::Rect_<__primitive_t>> &default_boxes);

    template <typename __primitive_t>
    void formatBBoxes(std::vector<cv::Rect_<__primitive_t>> &formatted_boxes, const std::vector<cv::Rect_<__primitive_t>> &boxes,
                      size_t width, size_t height);

    template <typename __primitive_t> double IoU(const cv::Rect_<__primitive_t> &pred, const cv::Rect_<__primitive_t> &gt);

    std::vector<DetectionResult> NMS(std::vector<DetectionResult> &_predictions, float _area_threshold,
                                     std::size_t _max_detections);

    sIrpPluginConfig m_config;
};

} // namespace irp
} // namespace imif

#endif //of _IRP_PLUGIN_SSDRESNET34_H
