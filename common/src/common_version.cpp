
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

#include <cstdio>

#include "easylogging++.h"
#include "common_version.h"

using namespace imif::common;

constexpr char version::INVALID_VERSION_STRING[];
constexpr char version::INVALID_TIMESTAMP_STRING[];

// Static variable declaration
version::imif_common_version_map_t version::s_imif_common_version_map;

version::version(std::string ver, std::string build_date, std::string build_rev)
{
    s_imif_common_version_map.clear();
    set_module_version("__main__", ver, build_date, build_rev);
}

void version::set_module_version(std::string so_name, std::string ver, std::string build_date, std::string build_rev)
{
    s_imif_common_version_map[so_name] = std::make_tuple(ver, build_date, build_rev);
}

std::string version::get_module_version(const std::string &module_name)
{
    return std::get<0>(s_imif_common_version_map[module_name]);
}

std::string version::get_module_timestamp(const std::string &module_name)
{
    return std::get<1>(s_imif_common_version_map[module_name]);
}

std::string version::get_module_revision(const std::string &module_name)
{
    return std::get<2>(s_imif_common_version_map[module_name]);
}

std::string version::version_to_string(const sBinaryVersion &version)
{
    std::stringstream ss;
    ss << static_cast<uint32_t>(version.major) << "." << static_cast<uint32_t>(version.minor) << "."
       << static_cast<uint32_t>(version.build_number);

    return ss.str();
}

sBinaryVersion version::version_from_string(const std::string &version)
{
    sBinaryVersion ret = {};
    if (version.empty())
        return ret;
    char delim = 0; // hold on '.' delimiter from version string "X.X.X"
    uint32_t arr[3] = {0, 0, 0};
    std::stringstream ss(version);
    ss >> arr[0] >> delim >> arr[1] >> delim >> arr[2];
    ret.major = static_cast<uint8_t>(arr[0]);
    ret.minor = static_cast<uint8_t>(arr[1]);
    ret.build_number = static_cast<uint16_t>(arr[2]);
    return ret;
}

static std::string get_last_path(std::string path)
{
    auto delim_index = path.find_last_of("/");
    if (std::string::npos == delim_index) {
        return path;
    }

    auto last_path = path.substr(delim_index + 1);
    if (0 < last_path.length()) {
        return last_path;
    }

    auto start_index = path.find_last_of("/", delim_index - 1);
    if (std::string::npos == start_index) {
        return path.substr(0, delim_index - 1);
    } else {
        return path.substr(start_index + 1, delim_index - 1);
    }
}

void version::print_version(bool verbose, const std::string &name, const std::string &description)
{
    std::cout << name << " " << version::get_module_version() << " (" << version::get_module_timestamp() << ") ["
              << version::get_module_revision() << "]" << std::endl;

    if (description.length() > 0) {
        std::cout << description << std::endl;
    }
    std::cout << "Copyright (c) 2019 Intel Corporation, All Rights Reserved." << std::endl << std::endl;
    if (verbose) {
        if (s_imif_common_version_map.size() > 1) {
            std::cout << "Additional Modules:" << std::endl;
            for (auto &module_node : s_imif_common_version_map) {
                if (module_node.first != "__main__") {
                    std::cout << std::string("  ") << module_node.first << std::string(": ") << std::get<0>(module_node.second)
                              << " (" << std::get<1>(module_node.second) << ") [" << std::get<2>(module_node.second) << "]"
                              << std::endl;
                }
            }
        }

        std::cout << "Platform: " << version::get_cpuid() << std::endl;
        std::cout << "Kernel Version: " << version::get_kernel_version() << std::endl;
    }
}

void version::log_version(int, char **argv)
{
    std::string name(get_last_path(argv[0]));

    LOG(INFO) << name << " " << version::get_module_version() << " (" << version::get_module_timestamp() << ") ["
              << version::get_module_revision() << "]";

    if (s_imif_common_version_map.size() > 1) {
        LOG(INFO) << "Additional Modules:";
        for (auto &module_node : s_imif_common_version_map) {
            if (module_node.first != "__main__") {
                LOG(INFO) << std::string("  ") << module_node.first << std::string(": ") << std::get<0>(module_node.second) << " ("
                          << std::get<1>(module_node.second) << ") [" << std::get<2>(module_node.second) << "]";
            }
        }
    }

    LOG(INFO) << "Platform: " << version::get_cpuid();
    LOG(INFO) << "Kernel Version: " << version::get_kernel_version();
}

bool version::handle_version_query(int argc, char **argv, const std::string &description)
{
    if (argc > 1) {
        bool version = false;
        bool all = false;
        for (int i = 1; i < argc; ++i) {
            if ((std::string("-v") == argv[i]) || (std::string("--version") == argv[i])) {
                version = true;
            } else if ((std::string("-va") == argv[i]) || (std::string("--version-all") == argv[i])) {
                version = true;
                all = true;
            }
        }

        if (version) {
            print_version(all, get_last_path(argv[0]), description);
            return true;
        }
    }
    return false;
}

std::string version::get_cpuid()
{
    std::string cpuid;
    std::string cpuid_file_name = "/proc/cpuinfo";
    std::ifstream cpuid_file(cpuid_file_name);

    if (cpuid_file.fail()) {
        LOG(ERROR) << "get_cpuid failed to access cpuinfo.";
        return cpuid;
    }

    std::string line;
    std::string model;
    while (std::getline(cpuid_file, line)) {
        auto machine_line = line.find("machine");
        if (std::string::npos != machine_line) {
            auto value_start = line.find(":", 7);
            if (std::string::npos != value_start) {
                cpuid = line.substr(value_start + 2);
                return cpuid;
            }
        }
        if (0 == model.length()) {
            auto model_line = line.find("model name");
            if (std::string::npos != model_line) {
                auto value_start = line.find(":");
                if (std::string::npos != value_start) {
                    model = line.substr(value_start + 2);
                }
            }
        }
    }

    if (0 < model.length()) {
        return model;
    }

    LOG(ERROR) << "failed to parse cpuinfo.";
    return cpuid;
}

std::string version::get_kernel_version()
{
    std::string kernel_version;
    std::string kernel_version_file_name = "/proc/sys/kernel/osrelease";
    std::ifstream kernel_version_file(kernel_version_file_name);

    if (kernel_version_file.fail()) {
        LOG(INFO) << "get_kernel_version failed.";
        return kernel_version;
    }

    kernel_version_file >> kernel_version;
    return kernel_version;
}
