
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

#include "irp_resnet50.h"
#include <numeric>

using namespace imif;
using namespace common;
using namespace irp;
using namespace cv;

static inline std::string &trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

float ConvertHalfToFloat(uint16_t in)
{
    const uint16_t s_mask = 0x8000;
    const uint16_t e_mask = 0x7c00;
    const uint16_t m_mask = 0x03ff;
    const int s = (in & s_mask) ? -1 : 1;
    const int e = (in & e_mask) >> 10;
    const int m = (in & m_mask);
    if (!e) {
        return float(s * m) / (1 << 24);
    }
    if (e == 0x1f) {
        return m ? std::numeric_limits<float>::quiet_NaN() : s * std::numeric_limits<float>::infinity();
    }
    float tmp = s * (1 + float(m) / (1 << 10));
    const int new_e = e - 0xf;
    return new_e >= 0 ? tmp * (1 << new_e) : tmp / (1 << (-new_e));
}

//sorting utility to get the top N results.
std::vector<size_t> GetTopN(const std::vector<float> &in, size_t n)
{
    std::vector<size_t> res(std::min(in.size(), n));
    std::vector<size_t> indexes(in.size());
    std::iota(indexes.begin(), indexes.end(), 0);
    std::partial_sort_copy(indexes.cbegin(), indexes.cend(), res.begin(), res.end(),
                           [&](size_t l, size_t r) { return in[l] > in[r]; });
    return res;
}

IrpPluginResnet50::IrpPluginResnet50() { m_labels.clear(); }

IrpPluginResnet50::~IrpPluginResnet50() {}

eIrpPluginStatus IrpPluginResnet50::initPlugin(sIrpPluginConfig irpPluginConfig)
{
    //load lables from file
    std::ifstream inputFile(irpPluginConfig.labels_file);
    if (!inputFile.is_open()) {
        LOG(FATAL) << "Can't find labels file: " << irpPluginConfig.labels_file;
        return IRP_PLUGIN_ERROR;
    }

    std::string strLine;
    while (std::getline(inputFile, strLine)) {
        trim(strLine);
        m_labels.push_back(strLine);
    }
    inputFile.close();

    return IRP_PLUGIN_NO_ERROR;
}

eIrpPluginStatus IrpPluginResnet50::postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob,
                                                size_t blobByteSize, uint32_t image_id, std::vector<sInferenceResult> &results)
{
    const size_t output_size = 1000;
    float max_probability = 0;
    uint32_t top_result = UINT32_MAX;
    float *output_blob = (float *)pOutputBlob;
    if (blobByteSize < output_size * image_id) {
        LOG(ERROR) << "Not enough inference data";
        return IRP_PLUGIN_ERROR;
    }
    output_blob = &output_blob[output_size * image_id];
    for (uint32_t i = 0; i < output_size; i++) {
        if (output_blob[i] > max_probability) {
            max_probability = output_blob[i];
            top_result = i;
        }
    }
    std::string label = (top_result < m_labels.size()) ? m_labels[top_result] : "NOT FOUND (" + std::to_string(top_result) + ")";

    sInferenceResult classified_object;
    classified_object.label = label;
    classified_object.probability = max_probability;
    classified_object.box.x = 0;
    classified_object.box.y = 0;
    classified_object.box.width = 0;
    classified_object.box.height = 0;

    results.push_back(classified_object);

    return IRP_PLUGIN_NO_ERROR;
}

extern "C" IrpPlugin &get_plugin()
{
    static IrpPluginResnet50 plugin;
    return plugin;
}
