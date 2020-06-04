
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

#include "irp_ssd_resnet34.h"

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

double *IrpPluginSsdResnet34::softmax(float *src, size_t nvars, size_t n)
{
    if (n <= 0)
        return nullptr;
    if (nvars < 1)
        return nullptr;
    if (src == nullptr)
        return nullptr;

    size_t nentries = n / nvars;

    double *dst = (double *)malloc(sizeof(double) * n);
    double temp_buffer[nentries];

    Mat src_vector = Mat(1, n, CV_32F, src);
    Mat dst_vector = Mat(1, n, CV_64F, dst);

    Mat src_vector_double;
    src_vector.convertTo(src_vector_double, CV_64F);
    cv::exp(src_vector_double, dst_vector);

    Mat dst_vector_reshaped = Mat(nvars, nentries, CV_64F, dst);
    Mat reduced_vector = Mat(1, nentries, CV_64F, temp_buffer);

    cv::reduce(dst_vector_reshaped, reduced_vector, 0, CV_REDUCE_SUM, CV_64F);

    for (size_t i = 0; i < nvars; i++) {
        dst_vector_reshaped.row(i) /= reduced_vector;
    }

    return dst;
}

template <typename __primitive_t>
void IrpPluginSsdResnet34::scaleBack(std::vector<cv::Rect_<__primitive_t>> &regressed_boxes, const __primitive_t *predicted_boxes,
                                     const std::vector<cv::Rect_<__primitive_t>> &default_boxes)
{
    const float scale_xy = 0.1;
    const float scale_wh = 0.2;
    size_t nboxes = default_boxes.size();

    for (size_t i = 0; i < nboxes; i++) {
        cv::Rect_<__primitive_t> bbox;

        bbox.x = scale_xy * predicted_boxes[0 * nboxes + i];
        bbox.y = scale_xy * predicted_boxes[1 * nboxes + i];
        bbox.width = scale_wh * predicted_boxes[2 * nboxes + i];
        bbox.height = scale_wh * predicted_boxes[3 * nboxes + i];

        bbox.x = bbox.x * default_boxes[i].width + default_boxes[i].x;
        bbox.y = bbox.y * default_boxes[i].height + default_boxes[i].y;
        bbox.width = exp(bbox.width) * default_boxes[i].width;
        bbox.height = exp(bbox.height) * default_boxes[i].height;

        regressed_boxes.push_back(bbox);
    }

    return;
}

template <typename __primitive_t>
void IrpPluginSsdResnet34::formatBBoxes(std::vector<cv::Rect_<__primitive_t>> &formatted_boxes,
                                        const std::vector<cv::Rect_<__primitive_t>> &boxes, size_t width, size_t height)
{
    for (size_t i = 0; i < boxes.size(); i++) {
        cv::Rect_<__primitive_t> bbox;

        // assumes bounding boxes given in either 'ltbr' or 'xmin,ymin,width,height' format
        bbox.x = boxes[i].x * width;
        bbox.y = boxes[i].y * height;
        bbox.width = boxes[i].width * width;
        bbox.height = boxes[i].height * height;

        // xywh
        bbox.x -= 0.5f * bbox.width;
        bbox.y -= 0.5f * bbox.height;

        formatted_boxes.push_back(bbox);
    }
    return;
}

//Compute the ratio of the intersection area over union area between two bounding boxes.
template <typename __primitive_t>
double IrpPluginSsdResnet34::IoU(const cv::Rect_<__primitive_t> &pred, const cv::Rect_<__primitive_t> &gt)
{
    cv::Point_<__primitive_t> top_left;
    cv::Point_<__primitive_t> bottom_right;

    top_left.x = std::max(pred.x, gt.x);
    top_left.y = std::max(pred.y, gt.y);
    bottom_right.x = std::min(pred.x + pred.width, gt.x + gt.width);
    bottom_right.y = std::min(pred.y + pred.height, gt.y + gt.height);

    // compute the area of intersection rectangle
    __primitive_t interArea = std::max((__primitive_t)0, (__primitive_t)(bottom_right.x - top_left.x + 1)) *
                              std::max((__primitive_t)0, (__primitive_t)(bottom_right.y - top_left.y + 1));

    // compute the area of both the prediction and ground-truth
    // rectangles
    __primitive_t predBBoxArea = pred.width * pred.height;
    __primitive_t gtBBoxArea = gt.width * gt.height;

    // compute the intersection over union by taking the intersection
    // area and dividing it by the sum of prediction + ground-truth
    // areas - the interesection area
    double iou = interArea / double(predBBoxArea + gtBBoxArea - interArea);

    return iou;
}

// apply NMS Non-maximum suppression to given list of prediction
std::vector<DetectionResult> IrpPluginSsdResnet34::NMS(std::vector<DetectionResult> &_predictions, float _area_threshold,
                                                       std::size_t _max_detections)
{
    std::size_t n_predictions = _predictions.size();
    bool overlap_area_constraint = false;
    std::vector<DetectionResult> top_detections;

    for (size_t i = 0; i < n_predictions; i++) {
        for (size_t j = i + 1; j < n_predictions;) {
            overlap_area_constraint = IoU(_predictions[i].bounding_box, _predictions[j].bounding_box) > _area_threshold;

            // if intersection area over union area is sufficiently large
            if (_predictions[i].category_id == _predictions[j].category_id && overlap_area_constraint == true) {
                // remove the box holding lowest score
                if (_predictions[i].detection_score >= _predictions[j].detection_score) {
                    _predictions.erase(_predictions.begin() + j);
                    n_predictions = _predictions.size();
                } else {
                    _predictions.erase(_predictions.begin() + i);
                    n_predictions = _predictions.size();
                    i--;
                    break;
                }
            } else {
                j++;
            }
        }
    }

    for (size_t i = 0; i < std::min((uint)_max_detections, (uint)(_predictions.size() + 1)); i++) {
        auto max =
            std::max_element(_predictions.begin(), _predictions.end(), [](const DetectionResult &a, const DetectionResult &b) {
                return a.detection_score < b.detection_score;
            });

        top_detections.push_back(*max);
        _predictions.erase(max);
    }

    return top_detections;
}

IrpPluginSsdResnet34::IrpPluginSsdResnet34()
{
    m_default_boxes.clear();
    m_labels.clear();
}

IrpPluginSsdResnet34::~IrpPluginSsdResnet34() {}

eIrpPluginStatus IrpPluginSsdResnet34::initPlugin(sIrpPluginConfig irpPluginConfig)
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
eIrpPluginStatus IrpPluginSsdResnet34::postProcess(imif::messages::types::FrameInfo &frame_info, void *pOutputBlob,
                                                   size_t blobByteSize, uint32_t image_id, std::vector<sInferenceResult> &results)
{
    std::vector<DetectionResult> detection_results;

    const size_t loc_size = 4 * 8732;
    const size_t n_classes = 81;
    const size_t n_bounding_boxes = 8732;
    const float detection_threshold = m_config.accuracy_threshold;
    const size_t batch_size = m_config.batch_size;
    float *blob = (float *)pOutputBlob;
    size_t image_width = frame_info.frame().width();
    size_t image_height = frame_info.frame().height();

    if (blobByteSize < loc_size * batch_size + n_bounding_boxes * n_classes * image_id) {
        LOG(ERROR) << "Not enough inference data.";
        return IRP_PLUGIN_ERROR;
    }

    float *pLoc = &blob[loc_size * image_id];
    float *pConf = &blob[loc_size * batch_size + n_bounding_boxes * n_classes * image_id];

    std::vector<cv::Rect_<float>> regressed_boxes;
    std::vector<cv::Rect_<float>> formatted_boxes;

    double *scores = softmax(pConf, n_classes, n_classes * n_bounding_boxes);
    if (!scores) {
        LOG(ERROR) << "Failed sofmax";
        return IRP_PLUGIN_ERROR;
    }

    //Compute the bounding boxes for each feature map of the network given their prior boxes
    scaleBack(regressed_boxes, pLoc, m_default_boxes);
    formatBBoxes(formatted_boxes, regressed_boxes, image_width, image_height);

    for (size_t j = 1; j < n_classes; j++) {
        for (size_t i = 0; i < n_bounding_boxes; i++) {
            float conf = scores[j * n_bounding_boxes + i];
            if (conf > detection_threshold) {
                DetectionResult detection;
                detection.label = j;
                detection.category_id = j;
                detection.detection_score = conf;
                detection.bounding_box = formatted_boxes[i];
                detection_results.push_back(detection);
            }
        }
    }

    free(scores);
    scores = nullptr;

    //adjust boxes to frame dimensions
    float width_aspect_ratio = 300.0f / image_width;
    float height_aspect_ratio = 300.0f / image_height;
    for (DetectionResult &det : detection_results) {
        det.bounding_box.x /= width_aspect_ratio;
        det.bounding_box.y /= height_aspect_ratio;

        det.bounding_box.x = (det.bounding_box.x < 0.0f) ? 0.0f : det.bounding_box.x;
        det.bounding_box.y = (det.bounding_box.y < 0.0f) ? 0.0f : det.bounding_box.y;

        det.bounding_box.width /= width_aspect_ratio;
        det.bounding_box.height /= height_aspect_ratio;
        if (det.bounding_box.x + det.bounding_box.width > image_width) {
            det.bounding_box.width = image_width - det.bounding_box.x;
        }
        if (det.bounding_box.y + det.bounding_box.height > image_height) {
            det.bounding_box.height = image_height - det.bounding_box.y;
        }
    }

    //remove overlapping area and extract the top boxes
    if (detection_results.size() > 0) {
        detection_results = NMS(detection_results, 0.65, m_config.max_number_of_objects);
    }

    //copy to results
    for (DetectionResult &det : detection_results) {
        sInferenceResult result;
        result.label = det.label < m_labels.size() ? m_labels[det.label] : "LABEL_NOT_FOUND_" + std::to_string(det.label);
        result.probability = det.detection_score;
        result.box.x = det.bounding_box.x;
        result.box.y = det.bounding_box.y;
        result.box.width = det.bounding_box.width;
        result.box.height = det.bounding_box.height;
        results.push_back(result);
    }

    return IRP_PLUGIN_NO_ERROR;
}

extern "C" IrpPlugin &get_plugin()
{
    static IrpPluginSsdResnet34 plugin;
    return plugin;
}
