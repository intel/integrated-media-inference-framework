
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

#ifndef _HEADER_H_
#define _HEADER_H_

#include <cstdint>
#include <messages/proto/enums.pb.h>

namespace imif {
namespace messages {

struct sProtoHeader {
    uint32_t magic;
    uint32_t opcode;
    uint32_t length;
    sProtoHeader()
    {
        magic = enums::MAGIC;
        opcode = enums::INVALID;
        length = 0;
    }
};

} // namespace messages
} // namespace imif

#endif // _HEADER__
