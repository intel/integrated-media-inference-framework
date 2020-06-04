
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

#ifndef _COMMON_STRING_UTILS_H_
#define _COMMON_STRING_UTILS_H_

#include <stdint.h>
#include <string.h>

#include <cstddef>
#include <string>
#include <vector>

namespace imif {
namespace common {

class string_utils {
public:
    ///
    /// @brief trim whitespace in place from the head of a string.
    ///
    static void ltrim(std::string &, std::string additional_chars = std::string());

    ///
    /// @brief trim whitespace in place from the tail of a string.
    ///
    static void rtrim(std::string &, std::string additional_chars = std::string());

    ///
    /// @brief trim whitespace in place from the head and tail of a string.
    ///
    static void trim(std::string &, std::string additional_chars = std::string());

    ///
    /// @brief get a head trimmed substring from provided string
    ///
    /// @return string the resulting trimmed substring
    ///
    static std::string ltrimmed_substr(const std::string &);

    ///
    /// @brief get a tail trimmed substring from provided string
    ///
    /// @return string the resulting trimmed substring
    ///
    static std::string rtrimmed_substr(const std::string &);

    ///
    /// @brief get a head and tail trimmed substring from provided string
    ///
    /// @return string the resulting trimmed substring
    ///
    static std::string trimmed_substr(const std::string &);

    ///
    /// @brief get a head and tail trimmed substring from provided string
    ///
    /// @return string representation of the boolean value ["true" | "false"]
    ///
    static std::string bool_str(bool val);

    static bool caseless_eq(const std::string &stra, const std::string &strb);

    static void copy_string(char *dst, const char *src, size_t dst_len);

    static std::vector<std::string> str_split(const std::string &s, char delim);

    static std::string int_to_hex_string(const unsigned int integer, const uint8_t number_of_digits);

    static size_t dump_bin2file(std::string fname, uint8_t *data, uint32_t data_len, bool append = true);

    static uint32_t stou(const std::string &str);
};
} // namespace common
} // namespace imif

#endif //__STRING_UTILS_H_
