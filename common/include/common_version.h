
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

#ifndef __COMMON_VERSION_H_
#define __COMMON_VERSION_H_

#include "common_defines.h"
#include <map>
#include <tuple>

namespace imif {
namespace common {

// This will default the version to 0.0.0 if not supplied by the Makefile. This will never
// happen with our current Makefiles as the version gets baked into the command line in
// the base build/common.mk but if this code is ever repurposed this will prevent a compile
// error.
#ifndef COMMON_VERSION
#define COMMON_VERSION "0.0.0"
#endif

#ifndef COMMON_BUILD_DATE
#define COMMON_BUILD_DATE "00/00/00--00:00"
#endif

#ifndef COMMON_REVISION
#define COMMON_REVISION "INVALID"
#endif

// must be included once and only once in file with main()
#define INIT_IMIF_VERSION                                                                                                          \
    static imif::common::version s_imif_common_version_map(std::string(IMIF_VERSION), std::string(IMIF_BUILD_DATE),                \
                                                           std::string(IMIF_REVISION));

#define INIT_IMIF_VERSION_SO(so_name)                                                                                              \
    __attribute__((constructor)) static void _version_register_module()                                                            \
    {                                                                                                                              \
        imif::common::version::s_imif_common_version_map[so_name] = std::make_tuple(            \
        imif::common::version::set_module_version(std::version(so_name),            \
            std::string(IMIF_VERSION),                                      \
            std::string(IMIF_BUILD_DATE),                                   \
            std::string(IMIF_REVISION));                                                                                           \
    }

typedef struct sBinaryVersion {
    uint8_t major;
    uint8_t minor;
    uint16_t build_number;
} sBinaryVersion;

class version {
public:
    static constexpr sBinaryVersion INVALID_VERSION = {};
    static constexpr char INVALID_VERSION_STRING[] = "0.0.0";
    static constexpr char INVALID_TIMESTAMP_STRING[] = "00/00/00--00:00";

    // Constructor
    version(std::string ver, std::string build_date, std::string build_rev);

    static void print_version(bool verbose, const std::string &name, const std::string &description = std::string());
    static bool handle_version_query(int argc, char **argv, const std::string &description = std::string());
    static void log_version(int argc, char **argv);

    static void set_module_version(std::string so_name, std::string ver, std::string build_date, std::string build_rev);
    static std::string get_module_version(const std::string &module_name = std::string("__main__"));
    static std::string get_module_timestamp(const std::string &module_name = std::string("__main__"));
    static std::string get_module_revision(const std::string &module_name = std::string("__main__"));
    static std::string version_to_string(const sBinaryVersion &version);
    static sBinaryVersion version_from_string(const std::string &version);

    static std::string get_cpuid();
    static std::string get_kernel_version();

private:
    // Version, Build Date, GIT Revision
    typedef std::map<std::string, std::tuple<std::string, std::string, std::string>> imif_common_version_map_t;
    static imif_common_version_map_t s_imif_common_version_map;
};

} // namespace common
} // namespace imif

#endif // __COMMONVERSION_H_
