
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

#ifndef _COMMON_LOGGING_H_
#define _COMMON_LOGGING_H_

#include <map>
#include <set>
#include <string>

#include "easylogging++.h"
#include "common_defines.h"
#include "common_string_utils.h"

namespace imif {
namespace common {

#define CONSOLE_MSG(a)                                                                                                             \
    do {                                                                                                                           \
        std::cout << a << "\r\n" << std::flush;                                                                                    \
    } while (0)
#define CONSOLE_MSG_INPLACE(a)                                                                                                     \
    do {                                                                                                                           \
        std::cout << "\r" << a << std::flush;                                                                                      \
    } while (0)

extern const std::string _LOGGING_MODULE_NAME;
#define _INIT_LOGGING(module_name) const std::string ::_LOGGING_MODULE_NAME = (module_name);

class log_levels {
public:
    typedef std::set<std::string> set_t;

    log_levels() = default;
    ~log_levels() = default;
    log_levels(const std::set<std::string> &log_levels);
    log_levels(const std::string &log_level_str);
    log_levels &operator=(const log_levels &rhs);
    log_levels &operator=(const std::string &log_level_str);
    log_levels operator&(const log_levels &rhs);

    std::string to_string();
    void parse_string(const std::string &log_level_str);

    bool is_all();
    bool is_off();

    bool fatal_enabled();
    bool error_enabled();
    bool warning_enabled();
    bool info_enabled();
    bool debug_enabled();
    bool trace_enabled();

    void set_log_level_state(const eLogLevel &log_level, const bool &new_state);

private:
    std::set<std::string> m_level_set;
};

extern const log_levels LOG_LEVELS_ALL;
extern const log_levels LOG_LEVELS_OFF;
extern const log_levels LOG_LEVELS_GLOBAL_DEFAULT;
extern const log_levels LOG_LEVELS_MODULE_DEFAULT;
extern const log_levels LOG_LEVELS_SYSLOG_DEFAULT;

class logging {
public:
    typedef std::map<std::string, std::string> settings_t;

    logging(const std::string config_path = std::string(), std::string module_name = _LOGGING_MODULE_NAME);
    logging(bool cache_settings = false, std::string module_name = _LOGGING_MODULE_NAME, const settings_t *settings = nullptr);
    ~logging() = default;

    void apply_settings();

    std::string get_module_name();

    void set_log_path(std::string log_path);
    std::string get_log_path();
    std::string get_log_filepath();
    std::string get_log_filename();
    std::string get_log_max_size_setting();
    log_levels get_log_levels();
    log_levels get_syslog_levels();

    void set_log_level_state(const eLogLevel &log_level, const bool &new_state);
    void set_log_level(const std::string &log_levels_str);

    // TBD: Can/Should these be removed?
    size_t get_log_rollover_size();
    size_t get_log_max_size();

protected:
    bool load_settings(const std::string &config_file_path);
    std::string get_config_path(std::string config_path);
    std::string get_cache_path();
    bool save_settings(const std::string &config_file_path);

    void eval_settings();

private:
    static const std::string format;

    std::string m_module_name;

    size_t m_logfile_size;
    std::string m_log_path;
    std::string m_log_filename;
    log_levels m_levels;
    log_levels m_syslog_levels;
    std::string m_netlog_host;
    uint16_t m_netlog_port;

    settings_t m_settings;
};

} // namespace common
} // namespace imif

#endif // _COMMON_LOGGING_H_
