
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

#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <experimental/filesystem>

#include "common_os_utils.h"
#include "common_string_utils.h"
#include <easylogging++.h>

using namespace imif::common;

namespace fs = std::experimental::filesystem;

std::string os_utils::get_process_path()
{
    char exe_path[PATH_MAX] = {0};
    if (-1 == readlink("/proc/self/exe", exe_path, sizeof(exe_path))) {
        LOG(ERROR) << "unable to determine execution path";
    }
    return std::string(exe_path);
}

std::string os_utils::get_process_dir()
{
    auto exe_path = get_process_path();
    auto dir_end = exe_path.find_last_of("/");
    return exe_path.substr(0, dir_end);
}

int os_utils::get_pid() { return getpid(); }

void os_utils::close_stdout_stderr()
{
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

bool os_utils::make_dir(std::string dir_path)
{ // check / create directory
    if (mkdir(dir_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0) {
        return true;
    }
    if (fs::is_directory(dir_path)) {
        return true;
    }
    return false;
}

void os_utils::abortExit(std::string msg)
{
    LOG(ERROR) << "AbortExit: " << msg;
    std::cout << "AbortExit: " << msg << std::endl;
    exit(0);
}

bool os_utils::is_directory(const std::string &path) { return fs::is_directory(path); }

bool os_utils::read_file_chunk(messages::mgmt::SendChunk &sendFile)
{
    std::string filename = sendFile.filename();
    auto file_pos = sendFile.file_pos();
    std::ifstream input_stream(filename, std::ios::binary);
    if (!input_stream.is_open()) {
        LOG(ERROR) << "ERROR: Could not open file " << filename << " !!\n";
        return false;
    }
    input_stream.seekg(0, input_stream.end);
    uint64_t length = input_stream.tellg();
    input_stream.seekg(file_pos, input_stream.beg);
    length -= input_stream.tellg();

    if (length > MAX_CHUNK_SIZE) {
        length = MAX_CHUNK_SIZE;
    } else {
        sendFile.set_is_last_chunk(true);
        if (length == 0) {
            LOG(ERROR) << "Got empty chunk";
            input_stream.close();
            return true;
        }
    }

    char *buffer = new char[length];
    input_stream.read(buffer, length);

    sendFile.set_content(buffer, length);
    delete[] buffer;
    input_stream.close();
    return true;
}

std::pair<std::shared_ptr<std::ofstream>, std::shared_ptr<std::ofstream>> os_utils::redirect_console_std(std::string log_file_name)
{
    close_stdout_stderr();
    
    auto stdout_fs = std::make_shared<std::ofstream>(log_file_name);
    auto stderr_fs = std::make_shared<std::ofstream>(log_file_name);
    
    return {stdout_fs, stderr_fs};
}

