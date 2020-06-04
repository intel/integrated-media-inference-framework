
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

#include "common_string_utils.h"

#include "easylogging++.h"

#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace imif::common;

static const std::string WHITESPACE_CHARS(" \t\n\r\f\v");

void string_utils::ltrim(std::string &str, std::string additional_chars)
{
    str.erase(0, str.find_first_not_of(WHITESPACE_CHARS + additional_chars));
}

void string_utils::rtrim(std::string &str, std::string additional_chars)
{
    str.erase(str.find_last_not_of(WHITESPACE_CHARS + additional_chars) + 1);
}

void string_utils::trim(std::string &str, std::string additional_chars)
{
    ltrim(str, additional_chars);
    rtrim(str, additional_chars);
}

std::string string_utils::ltrimmed_substr(const std::string &str)
{
    auto start = str.find_first_not_of(WHITESPACE_CHARS);
    if (std::string::npos != start) {
        return str.substr(start);
    }
    return std::string();
}

std::string string_utils::rtrimmed_substr(const std::string &str)
{
    auto end = str.find_last_not_of(WHITESPACE_CHARS);
    if (std::string::npos != end) {
        return str.substr(0, end + 1);
    }
    return std::string();
}

std::string string_utils::trimmed_substr(const std::string &str)
{
    auto start = str.find_first_not_of(WHITESPACE_CHARS);
    auto end = str.find_last_not_of(WHITESPACE_CHARS);
    if ((std::string::npos != start) && (std::string::npos != end)) {
        return str.substr(start, end - start + 1);
    }
    return std::string();
}

std::string string_utils::bool_str(bool val) { return (val) ? std::string("true") : std::string("false"); }

bool string_utils::caseless_eq(const std::string &stra, const std::string &strb)
{
    return stra.size() == strb.size() &&
           std::equal(std::begin(stra), std::end(stra), std::begin(strb),
                      [](const char &cha, const char &chb) { return std::tolower(cha) == std::tolower(chb); });
}

void string_utils::copy_string(char *dst, const char *src, size_t dst_len)
{
    const char *src_end = std::find((char *)src, ((char *)src) + dst_len, '\0');
    std::copy(src, src_end, dst);
    std::ptrdiff_t src_size = src_end - src;
    std::ptrdiff_t dst_size = dst_len;
    if (src_size < dst_size) {
        dst[src_size] = 0;
    } else {
        dst[dst_size - 1] = 0;
        LOG(ERROR) << "copy_string() overflow, src string:'" << src << "'"
                   << " dst_size=" << dst_size << std::endl;
    }
}

std::vector<std::string> string_utils::str_split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }

    return elems;
}

std::string string_utils::int_to_hex_string(const unsigned int integer, const uint8_t number_of_digits)
{
    // 'number_of_digits' represent how much digits the number should have, so the function will
    // pad the number with zeroes from left, if necessary.
    // for example: int_to_hex_string(255, 4) -> "00ff"
    //              int_to_hex_string(255, 1) -> "ff"

    std::string return_string;
    std::stringstream ss_hex_string;

    // convert to hex
    ss_hex_string << std::setw(number_of_digits) << std::setfill('0') << std::hex << integer;

    return ss_hex_string.str();
}

size_t string_utils::dump_bin2file(std::string fname, uint8_t *data, uint32_t data_len, bool append)
{
    std::ofstream dump_fs(fname.c_str(), std::ios::binary | std::ios::out | (append ? std::ios::app : std::ios::trunc));

    if (!dump_fs.is_open()) {
        return false;
    }

    auto before = dump_fs.tellp();
    dump_fs.write((const char *)data, data_len);
    dump_fs.close();

    size_t written = dump_fs.tellp() - before;

    return written;
}

uint32_t string_utils::stou(const std::string &str)
{
    int64_t temp_val = std::stoll(str);
    if (temp_val < 0 || temp_val > std::numeric_limits<uint32_t>::max()) {
        throw std::out_of_range("Can't convert " + str + " to uint32_t - out_of_range");
    }

    return temp_val;
}
