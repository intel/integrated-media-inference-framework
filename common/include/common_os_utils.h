
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

#ifndef _COMMON_OS_UTILS_H_
#define _COMMON_OS_UTILS_H_

#include <map>
#include <messages/proto/mgmt.pb.h>
#include <set>
#include <string>

#include <unistd.h>
#define UTILS_SLEEP_MSEC(msec) usleep(msec * 1000)

namespace imif {
namespace common {

class os_utils {
public:
    ///
    /// @brief Function to get current process executable path
    ///
    /// @return string containing executable binary path location.
    ///     if information can't be acquired.
    ///
    static std::string get_process_path();

    ///
    /// @brief Function to get current process directory
    ///
    /// @return string containing the directory where the executable binary is located.
    ///
    static std::string get_process_dir();

    static int get_pid();

    static void close_stdout_stderr();

    static bool make_dir(std::string dir_path);

    static void abortExit(std::string msg);

    static bool is_directory(const std::string &path);

    static bool read_file_chunk(messages::mgmt::SendChunk &send_chunk);
    
    static std::pair<std::shared_ptr<std::ofstream>, std::shared_ptr<std::ofstream>> redirect_console_std(std::string log_file_name = "/dev/null");

    static const uint64_t MAX_CHUNK_SIZE = 32768;
};
} // namespace common
} // namespace imif

#endif //__OS_UTILS_H_
