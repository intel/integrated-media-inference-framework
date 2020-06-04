
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

#include "irp_yolov3.h"

using namespace imif;
using namespace common;
using namespace irp;
using namespace cv;

//these values are hard coded for a specific network model, but can be obtained from the network properties.
const uint c_yolo3_classes = 80;
const uint c_yolo3_coords = 4;
const std::vector<size_t> c_yolo3_out_blob_layer_offsets = {0, 172380, (172380 + 689520)};
const std::vector<size_t> c_yolo3_out_blob_image_offsets = {172380, 689520, 43095};
const std::vector<int> c_yolo3_out_blob_h = {26, 52, 13};
const std::vector<std::vector<uint>> c_yolo3_mask = {{3, 4, 5}, {0, 1, 2}, {6, 7, 8}};

struct boxObject {
    int xmin, ymin, xmax, ymax;
    uint class_id;
    float confidence;

    boxObject(double x, double y, double h, double w, int class_id, float confidence, float h_scale, float w_scale)
    {
        this->xmin = static_cast<int>((x - w / 2) * w_scale);
        this->ymin = static_cast<int>((y - h / 2) * h_scale);
        this->xmax = static_cast<int>(this->xmin + w * w_scale);
        this->ymax = static_cast<int>(this->ymin + h * h_scale);
        this->class_id = class_id;
        this->confidence = confidence;
    }

    bool operator<(const boxObject &s2) const { return this->confidence < s2.confidence; }
    bool operator>(const boxObject &s2) const { return this->confidence > s2.confidence; }
};

static inline std::string &trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

static int getIdx(int side, int location, int entry)
{
    int side_pow = side * side;
    return ((location / side_pow) * side_pow * (c_yolo3_coords + c_yolo3_classes + 1)) + (entry * side_pow) + (location % side_pow);
}

static double checkBoxOverlapp(const boxObject &b1, const boxObject &b2)
{
    double b_x_m1 = fmin(b1.xmax, b2.xmax);
    double b_x_m2 = fmax(b1.xmin, b2.xmin);
    double width_overlap = b_x_m1 - b_x_m2;
    double b_y_m1 = fmin(b1.ymax, b2.ymax);
    double b_y_m2 = fmax(b1.ymin, b2.ymin);
    double height_overlap = b_y_m1 - b_y_m2;
    double overlap_area = (width_overlap < 0 || height_overlap < 0) ? 0 : (width_overlap * height_overlap);
    double union_area = ((b1.ymax - b1.ymin) * (b1.xmax - b1.xmin)) + ((b2.ymax - b2.ymin) * (b2.xmax - b2.xmin)) - overlap_area;
    return overlap_area / union_area;
}

static float calcObjCord(int n, int side, int side_pow, int side_idx, int row, int col, std::vector<float> &anchors, float *blob,
                         int frame_height, int frame_width, double &x, double &y, double &height, double &width)
{
    int obj_index = getIdx(side, (n * side_pow) + side_idx, c_yolo3_coords);
    int box_index = getIdx(side, (n * side_pow) + side_idx, 0);
    x = (col + blob[box_index + 0 * side_pow]) / side * frame_width;
    y = (row + blob[box_index + 1 * side_pow]) / side * frame_height;
    height = std::exp(blob[box_index + 3 * side_pow]) * anchors[2 * n + 1];
    width = std::exp(blob[box_index + 2 * side_pow]) * anchors[2 * n];
    return float(blob[obj_index]); //scale
}

static float calcObjProb(int n, int side, int side_pow, int side_idx, uint class_idx, float scale, float *blob)
{
    int class_index = getIdx(side, n * side_pow + side_idx, c_yolo3_coords + 1 + class_idx);
    return (scale * blob[class_index]);
}

IrpPluginYolov3::IrpPluginYolov3()
{
    m_default_boxes.clear();
    m_labels.clear();
}

IrpPluginYolov3::~IrpPluginYolov3() {}

eIrpPluginStatus IrpPluginYolov3::initPlugin(sIrpPluginConfig irpPluginConfig)
{
    m_config = irpPluginConfig;

    //load lables from file
    std::ifstream inputFile(irpPluginConfig.labels_file, std::ios::in);
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

    //load default boxes
    std::string dBoxesFileName = irpPluginConfig.default_boxes_file;
    inputFile.open(dBoxesFileName, std::ios::in);
    if (!inputFile.is_open()) {
        inputFile.close();
        LOG(FATAL) << "Can't find default boxes file: " << dBoxesFileName;
        return IRP_PLUGIN_ERROR;
    }

    inputFile.seekg(0, inputFile.end);
    size_t length = inputFile.tellg();
    inputFile.seekg(0, inputFile.beg);

    char buffer[length];
    inputFile.read(buffer, length);
    inputFile.close();

    char delimiters[] = "\n ,";
    char *token = std::strtok(buffer, delimiters);

    while (token != NULL) {
        cv::Rect_<float> dbox;
        dbox.x = (float)std::strtof(token, NULL);

        if ((token = std::strtok(NULL, delimiters)) != NULL)
            dbox.y = (float)std::strtof(token, NULL);

        if ((token = std::strtok(NULL, delimiters)) != NULL)
            dbox.width = (float)std::strtof(token, NULL);

        if ((token = std::strtok(NULL, delimiters)) != NULL)
            dbox.height = (float)std::strtof(token, NULL);

        m_default_boxes.push_back(dbox);

        token = std::strtok(NULL, delimiters);
    }
    return IRP_PLUGIN_NO_ERROR;
}

//Initializes the plugin
eIrpPluginStatus IrpPluginYolov3::postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob, size_t blobByteSize,
                                              uint32_t image_id, std::vector<sInferenceResult> &results)
{
    std::vector<boxObject> objects;
    const uint frame_height = frame_info.frame().height();
    const uint frame_width = frame_info.frame().width();

    std::vector<float> anchors = {10.0, 13.0, 16.0,  30.0,  33.0, 23.0,  30.0,  61.0,  62.0,
                                  45.0, 59.0, 119.0, 116.0, 90.0, 156.0, 198.0, 373.0, 326.0};

    float *output_blob_start = (float *)pOutputBlob;

    //three Region-Yolo layers are output from this network
    //extract objects and boxes
    for (uint out_layer_idx = 0; out_layer_idx < 3; out_layer_idx++) {

        int num = c_yolo3_mask[out_layer_idx].size();
        std::vector<float> maskedAnchors(num * 2);
        for (int i = 0; i < num; ++i) {
            maskedAnchors[i * 2] = anchors[c_yolo3_mask[out_layer_idx].at(i) * 2];
            maskedAnchors[i * 2 + 1] = anchors[c_yolo3_mask[out_layer_idx].at(i) * 2 + 1];
        }
        anchors = maskedAnchors;

        auto side = c_yolo3_out_blob_h[out_layer_idx];
        auto side_pow = side * side;
        const int buffer_offset = (m_config.batch_size * c_yolo3_out_blob_layer_offsets[out_layer_idx]) +
                                  c_yolo3_out_blob_image_offsets[out_layer_idx] * image_id;
        float *blob = &output_blob_start[buffer_offset];
        double x = 0, y = 0, height = 0, width = 0;

        for (int side_idx = 0; side_idx < side_pow; side_idx++) {
            int row = side_idx / side;
            int col = side_idx % side;
            for (int n = 0; n < num; n++) {
                auto scale = calcObjCord(n, side, side_pow, side_idx, row, col, anchors, blob, frame_height, frame_width, x, y,
                                         height, width);
                if (scale < m_config.accuracy_threshold)
                    continue;
                for (uint class_idx = 0; class_idx < c_yolo3_classes; class_idx++) {
                    auto prob = calcObjProb(n, side, side_pow, side_idx, class_idx, scale, blob);
                    if (prob < m_config.accuracy_threshold)
                        continue;
                    boxObject obj(x, y, height, width, class_idx, prob, 1, 1);
                    objects.push_back(obj);
                }
            }
        }
    }

    //filter overlapping boxes
    const double IoT_threshold = 0.65;
    std::sort(objects.begin(), objects.end(), std::greater<boxObject>());
    for (size_t i = 0; i < objects.size(); ++i) {
        if (objects[i].confidence == 0)
            continue;
        for (size_t j = i + 1; j < objects.size(); ++j)
            if (checkBoxOverlapp(objects[i], objects[j]) >= IoT_threshold) {
                objects[j].confidence = 0;
            }
    }

    //convert boxes information to irp format
    for (auto object : objects) {
        sInferenceResult result;
        result.label =
            object.class_id < m_labels.size() ? m_labels[object.class_id] : "LABEL_NOT_FOUND_" + std::to_string(object.class_id);
        result.probability = object.confidence;
        result.box.x = object.xmin;
        result.box.y = object.ymin;
        result.box.width = object.xmax - object.xmin;
        result.box.height = object.ymax - object.ymin;

        results.push_back(result);
    }

    return IRP_PLUGIN_NO_ERROR;
}

extern "C" IrpPlugin &get_plugin()
{
    static IrpPluginYolov3 plugin;
    return plugin;
}
