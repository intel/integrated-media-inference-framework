
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

#ifndef _COMMON_MESSAGE_H_
#define _COMMON_MESSAGE_H_

#include "common_message.h"
#include <cstddef>
#include <stdint.h>

#define IMIF_UDS_MAGIC 0x55AA55CC

namespace imif {
namespace common {

enum eUdsCommands : uint8_t {
    CMD_INVALID = 0,
    CMD_ADD_STREAM = 1,
    CMD_REMOVE_STREAM = 2,
    CMD_DECODE_STREAM = 3,
    CMD_INFERENCE_STREAM = 4,
    CMD_INFERENCE_RESPONSE = 5,
};

typedef struct sUdsHeader {
    uint32_t magic;
    uint8_t stream_id;
    uint8_t reserved;
    eUdsCommands cmd;
    uint8_t width;
    uint8_t height;
    uint64_t frame_num;
    uint32_t length;

    sUdsHeader()
    {
        magic = IMIF_UDS_MAGIC;
        stream_id = 0;
        cmd = CMD_INVALID;
        length = 0;
    }
} sUdsHeader;

} // namespace common
} // namespace imif

#endif //_COMMON_MESSAGE_H_
