
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

#include "irp_default.h"

using namespace imif;
using namespace common;
using namespace irp;
using namespace cv;

IrpPluginDefault::IrpPluginDefault() {}

IrpPluginDefault::~IrpPluginDefault() {}

eIrpPluginStatus IrpPluginDefault::initPlugin(sIrpPluginConfig irpPluginConfig) { return IRP_PLUGIN_NO_ERROR; }

//Initializes the plugin
eIrpPluginStatus IrpPluginDefault::postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob, size_t blobByteSize,
                                               uint32_t image_id, std::vector<sInferenceResult> &results)
{
    return IRP_PLUGIN_NO_ERROR;
}

extern "C" IrpPlugin &get_plugin()
{
    static IrpPluginDefault plugin;
    return plugin;
}
