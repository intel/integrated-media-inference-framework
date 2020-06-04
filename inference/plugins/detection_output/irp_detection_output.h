
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

#ifndef _IRP_PLUGIN_DETECTIONOUTPUT_H
#define _IRP_PLUGIN_DETECTIONOUTPUT_H

#include "irp_plugin.h"

namespace imif {
namespace irp {

class IrpPluginDetectionOutput : public IrpPlugin {

public:
    IrpPluginDetectionOutput();
    ~IrpPluginDetectionOutput();

    //Initializes the plugin
    eIrpPluginStatus initPlugin(sIrpPluginConfig irpPluginConfig);

    //Initializes the plugin
    eIrpPluginStatus postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob, size_t blobByteSize,
                                 uint32_t image_id, std::vector<sInferenceResult> &results);

    private:
        std::vector<std::string> m_labels;
        sIrpPluginConfig m_config;

    const size_t MAX_NUMBER_OF_OBJECTS = 1000;
};

} // namespace irp
} // namespace imif

#endif //of _IRP_PLUGIN_DETECTIONOUTPUT_H
