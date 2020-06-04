
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

#ifndef _IRP_PLUGIN_H
#define _IRP_PLUGIN_H
#include "common_mem_manager.h"
#include <messages/proto/types.pb.h>
#include <stdio.h>
#include <string.h>

#include "easylogging++.h"
#include "opencv2/core/core_c.h"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/imgproc/types_c.h"
#include "opencv2/objdetect/objdetect.hpp"

enum eIrpPluginStatus {
    IRP_PLUGIN_NO_ERROR = 0x0,
    IRP_PLUGIN_ERROR = 0x1,
    IRP_PLUGIN_NOT_SUPPORTED = 0x2,
    IRP_PLUGIN_BUSY = 0x3,
};

namespace imif {
namespace irp {

struct sIrpPluginConfig {

    std::string labels_file;          // file path containing labels for the detected/classified objects
    std::string default_boxes_file;   // file path default/prior boxes requires for object detection
    float accuracy_threshold = 0;     // minimum accuracy threshold for the detected/classified object
    size_t max_number_of_objects = 0; // maximum number of objects to be detected/classified
    size_t batch_size = 0;

    sIrpPluginConfig()
    {
        labels_file.clear();
        default_boxes_file.clear();
    }
};

struct sInferredBox {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

struct sInferenceResult {
    std::string label;
    float probability;
    sInferredBox box;
};

class IrpPlugin {

public:
    IrpPlugin(){};
    virtual ~IrpPlugin(){};

    //Initializes the plugin
    virtual eIrpPluginStatus initPlugin(sIrpPluginConfig irpPluginConfig) = 0;

    //Initializes the plugin

    virtual eIrpPluginStatus postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob, size_t blobByteSize,
                                         uint32_t image_id, std::vector<sInferenceResult> &results) = 0;
};

} // namespace irp
} // namespace imif

#endif //of #ifndef _IRP_PLUGIN_H
