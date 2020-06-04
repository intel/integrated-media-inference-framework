
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

#ifndef _COMMON_DEFINES_H_
#define _COMMON_DEFINES_H_

#include <cstddef>
#include <stdint.h>

#include <memory>

template <typename T, typename... Args> std::unique_ptr<T> make_unique(Args &&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

namespace imif {
namespace common {

#define IMIF_BRK "imif_broker"
#define IMIF_MGMT "imif_mgmt"
#define IMIF_MSTREAM "imif_mstream"
#define IMIF_MDECODE "imif_mdecode"
#define IMIF_INFERENCE "imif_inference"
#define IMIF_PNPT "imif_pnpt"

enum eGlobalConsts {
    VERSION_LENGTH = 16,
};

enum eResult : uint32_t {
    RESULT_OK = 0u,
    RESULT_GENERAL_FAILURE = 2u,
    RESULT_INVALID_PARAMETER = 3u,
    RESULT_NOT_PRESENT = 4u,
    RESULT_NOT_IMPLEMENTED = 5u,
    RESULT_INTERNAL_ERROR = 6u,
    RESULT_NOT_INITIALIZED = 7u,
    RESULT_SOCKET_FAILURE = 8u,
    RESULT_ALREADY_INITIALIZED = 9u,
};

enum eLogLevel : uint8_t {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ALL,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_TRACE,
    LOG_LEVEL_WARNING,
};

} // namespace common
} // namespace imif

#endif //_COMMON_DEFINES_H_
