
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

#include "common_logging.h"
#include "easylogging++.h"
#include "common_os_utils.h"
#include "common_socket.h"

#include <algorithm>
#include <experimental/filesystem>
#include <iostream>
#include <linux/limits.h>
#include <unistd.h>

namespace fs = std::experimental::filesystem;

#define LOG_MAX_LEVELS 6
#define LOGGING_DEFAULT_MAX_SIZE (size_t)1000000000

// Use the easylogging++ instance from the parent process
// SHARE_EASYLOGGINGPP(el::Helpers::storage())

using namespace imif::common;

class NetLogger : public el::LogDispatchCallback {
public:
    void enable(const std::string &server, uint16_t port, std::string module_name)
    {
        m_server = server;
        m_port = port;
        m_module_name = module_name;
        this->setEnabled(true);
    }

protected:
    void handle(const el::LogDispatchData *logdata) noexcept override
    {
        std::string msg = m_module_name + ": " +
                          logdata->logMessage()->logger()->logBuilder()->build(
                              logdata->logMessage(), logdata->dispatchAction() == el::base::DispatchAction::NormalLog);
        SocketClient logmaster(m_server, m_port);
        logmaster.writeString(msg);
    }

private:
    std::string m_server;
    uint16_t m_port;
    std::string m_module_name;
};

static std::string log_level_to_string(const eLogLevel &log_level)
{
    std::string log_level_str;
    switch (log_level) {
    case LOG_LEVEL_INFO:
        log_level_str = "info";
        break;
    case LOG_LEVEL_DEBUG:
        log_level_str = "debug";
        break;
    case LOG_LEVEL_ERROR:
        log_level_str = "error";
        break;
    case LOG_LEVEL_FATAL:
        log_level_str = "fatal";
        break;
    case LOG_LEVEL_TRACE:
        log_level_str = "trace";
        break;
    case LOG_LEVEL_WARNING:
        log_level_str = "warning";
        break;
    default:
        log_level_str = std::string();
        break;
    }
    return log_level_str;
}

//====================================================================================
// log_levels
//====================================================================================
namespace imif {
namespace common {
const log_levels LOG_LEVELS_ALL = log_levels(log_levels::set_t({"debug", "error", "fatal", "info", "trace", "warning"}));
const log_levels LOG_LEVELS_OFF = log_levels(log_levels::set_t());
const log_levels LOG_LEVELS_GLOBAL_DEFAULT = log_levels(log_levels::set_t({"error", "fatal", "warning"}));
const log_levels LOG_LEVELS_MODULE_DEFAULT = log_levels(log_levels::set_t({"debug", "error", "fatal", "info", "trace", "warning"}));
const log_levels LOG_LEVELS_SYSLOG_DEFAULT = log_levels(log_levels::set_t({"error", "fatal"}));
} // namespace common
} // namespace imif

using namespace imif::common;

log_levels::log_levels(const std::set<std::string> &log_levels) : m_level_set(log_levels) {}

log_levels::log_levels(const std::string &log_level_str) { parse_string(log_level_str); }

log_levels &log_levels::operator=(const log_levels &rhs)
{
    if (&rhs != this) {
        m_level_set = rhs.m_level_set;
    }
    return *this;
}

log_levels &log_levels::operator=(const std::string &log_level_str)
{
    m_level_set.clear();
    parse_string(log_level_str);
    return *this;
}

log_levels log_levels::operator&(const log_levels &rhs)
{
    set_t intersect;
    std::set_intersection(m_level_set.begin(), m_level_set.end(), rhs.m_level_set.begin(), rhs.m_level_set.end(),
                          std::inserter(intersect, intersect.begin()));
    return log_levels(intersect);
}

void log_levels::parse_string(const std::string &str)
{
    size_t token_start = 0;
    size_t token_end;
    do {
        token_end = str.find_first_of(",", token_start);
        std::string token;
        if (token_end != std::string::npos) {
            token = str.substr(token_start, token_end - token_start);
        } else {
            token = str.substr(token_start);
        }

        string_utils::trim(token);
        std::transform(token.begin(), token.end(), token.begin(), ::tolower);
        if ("all" == token) {
            // ignore any additional tokens
            token_end = std::string::npos;
            m_level_set = LOG_LEVELS_ALL.m_level_set;
        } else if ("off" == token) {
            // ignore any additional tokens
            token_end = std::string::npos;
            m_level_set = LOG_LEVELS_OFF.m_level_set;
        } else {
            if (LOG_LEVELS_ALL.m_level_set.end() != LOG_LEVELS_ALL.m_level_set.find(token)) {
                // valid token
                m_level_set.insert(token);
            } else {
                LOG(WARNING) << "loglevel invalid token: " << token;
                // ignore invalid tokens
            }
        }
        token_start = token_end + 1;
    } while (token_end != std::string::npos);
}

void log_levels::set_log_level_state(const eLogLevel &log_level, const bool &new_state)
{
    if (log_level == LOG_LEVEL_ALL) {
        if (new_state) {
            m_level_set = LOG_LEVELS_ALL.m_level_set;
        } else {
            m_level_set = LOG_LEVELS_OFF.m_level_set;
        }
    } else if (log_level != LOG_LEVEL_NONE) {
        std::string log_level_str = log_level_to_string(log_level);
        if (!log_level_str.empty()) {
            if (new_state) {
                m_level_set.insert(log_level_str);
            } else {
                m_level_set.erase(log_level_str);
            }
        }
    }
}

std::string log_levels::to_string()
{
    if (m_level_set.size() < 1) {
        return std::string();
    }

    std::string str;
    for (auto &elt : m_level_set) {
        str += elt + ", ";
    }
    str.erase(str.size() - 2);
    return str;
}

bool log_levels::is_all() { return (m_level_set.size() == LOG_MAX_LEVELS); }

bool log_levels::is_off() { return (m_level_set.size() == 0); }

bool log_levels::fatal_enabled() { return (m_level_set.end() != m_level_set.find("fatal")); }

bool log_levels::error_enabled() { return (m_level_set.end() != m_level_set.find("error")); }

bool log_levels::warning_enabled() { return (m_level_set.end() != m_level_set.find("warning")); }

bool log_levels::info_enabled() { return (m_level_set.end() != m_level_set.find("info")); }

bool log_levels::debug_enabled() { return (m_level_set.end() != m_level_set.find("debug")); }

bool log_levels::trace_enabled() { return (m_level_set.end() != m_level_set.find("trace")); }

//====================================================================================
// logging
//====================================================================================
const std::string logging::format("%level %datetime{%H:%m:%s:%g} %fbase:%line --> %msg"); //<%thread>

logging::logging(const std::string config_path, std::string module_name)
    : m_module_name(module_name), m_logfile_size(LOGGING_DEFAULT_MAX_SIZE), m_levels(LOG_LEVELS_GLOBAL_DEFAULT),
      m_syslog_levels(LOG_LEVELS_SYSLOG_DEFAULT), m_netlog_host(""), m_netlog_port(0)
{
    m_log_path = std::string();
    m_log_filename = std::string();
    m_settings.clear();

    bool found_settings = false;

    // check for cached settings
    found_settings = load_settings(get_cache_path());

    // if no cached settings are found, look for a config
    auto conf_path = get_config_path(config_path);
    if (!found_settings) {
        found_settings = load_settings(conf_path);
    }

    if (found_settings) {
        eval_settings();
    }
}

logging::logging(bool cache_settings, std::string module_name, const settings_t *settings)
    : m_module_name(module_name), m_logfile_size(LOGGING_DEFAULT_MAX_SIZE), m_levels(LOG_LEVELS_MODULE_DEFAULT),
      m_syslog_levels(LOG_LEVELS_SYSLOG_DEFAULT), m_netlog_host(""), m_netlog_port(0)
{
    m_settings.clear();
    if (settings) {
        for (auto &setting : *settings) {
            if (0 == setting.first.find("log_")) {
                m_settings.insert(setting);
            }
        }
    }

    if (cache_settings) {
        save_settings(get_cache_path());
    }

    eval_settings();
}

std::string logging::get_module_name() { return m_module_name; }

std::string logging::get_config_path(std::string config_path)
{
    if (config_path.length() > 0) {
        if ('/' != config_path[0]) {
            // config specifies a local path
            config_path = os_utils::get_process_dir() + "/" + config_path;
        }

        if (fs::is_regular_file(config_path)) {
            return config_path;
        }
        // conf file doesn't exist try
        config_path = config_path + "/" + m_module_name + ".conf";
    } else {
        // no config path provide, use default
        config_path = os_utils::get_process_dir() + "/" + m_module_name + ".conf";
    }
    return config_path;
}

std::string logging::get_cache_path() { return os_utils::get_process_dir() + "/." + m_module_name + ".cache.conf"; }

std::string logging::get_log_path()
{
    if (m_log_path.size() > 0) {
        return m_log_path;
    }
    return os_utils::get_process_dir();
}

std::string logging::get_log_filepath()
{
    auto path = get_log_path();
    auto filename = get_log_filename();

    return path + "/" + filename;
}

std::string logging::get_log_filename()
{
    if (m_log_filename.size() > 0) {
        return m_log_filename;
    }
    return m_module_name + ".%datetime{%Y%M%d_%H%m%s}.log";
}

std::string logging::get_log_max_size_setting()
{
    // Since we perform a semi-manual rolling, the maximal
    // allowed size is twice the specified value from the configuration
    // file (just in case our manual process will fail...)

    return std::to_string((unsigned long)(get_log_max_size() * 2));
}

size_t logging::get_log_max_size() { return m_logfile_size; }

size_t logging::get_log_rollover_size() { return m_logfile_size / 2; }

log_levels logging::get_log_levels() { return m_levels; }

log_levels logging::get_syslog_levels() { return m_syslog_levels; }

void logging::set_log_level_state(const eLogLevel &log_level, const bool &new_state)
{
    m_levels.set_log_level_state(log_level, new_state);
    apply_settings();
}

void logging::set_log_level(const std::string &log_level_str)
{
    m_levels = log_level_str;
    apply_settings();
}

void logging::apply_settings()
{
    el::Configurations defaultConf;
    defaultConf.setToDefault();
    defaultConf.setGlobally(el::ConfigurationType::Format, format);
    defaultConf.setGlobally(el::ConfigurationType::ToFile, "true");
    defaultConf.setGlobally(el::ConfigurationType::Filename, get_log_filepath().c_str());
    defaultConf.setGlobally(el::ConfigurationType::ToStandardOutput, "false");
    defaultConf.setGlobally(el::ConfigurationType::MaxLogFileSize, get_log_max_size_setting().c_str());

    defaultConf.set(el::Level::Fatal, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.fatal_enabled()));
    defaultConf.set(el::Level::Error, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.error_enabled()));
    defaultConf.set(el::Level::Warning, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.warning_enabled()));
    defaultConf.set(el::Level::Info, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.info_enabled()));
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.debug_enabled()));
    defaultConf.set(el::Level::Trace, el::ConfigurationType::Enabled, string_utils::bool_str(m_levels.trace_enabled()));

    // configure syslog settings
    el::Configurations syslogConf;
    syslogConf.setToDefault();
    syslogConf.setGlobally(el::ConfigurationType::Format, format);

    syslogConf.set(el::Level::Fatal, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.fatal_enabled()));
    syslogConf.set(el::Level::Error, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.error_enabled()));
    syslogConf.set(el::Level::Warning, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.warning_enabled()));
    syslogConf.set(el::Level::Info, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.info_enabled()));
    syslogConf.set(el::Level::Debug, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.debug_enabled()));
    syslogConf.set(el::Level::Trace, el::ConfigurationType::Enabled, string_utils::bool_str(m_syslog_levels.trace_enabled()));

    el::Loggers::reconfigureLogger("default", defaultConf);
    el::Loggers::reconfigureLogger("syslog", syslogConf);

    el::Loggers::addFlag(el::LoggingFlag::ImmediateFlush);
    el::Loggers::addFlag(el::LoggingFlag::LogDetailedCrashReason);
    el::Loggers::addFlag(el::LoggingFlag::DisableApplicationAbortOnFatalLog);
    el::Loggers::addFlag(el::LoggingFlag::StrictLogFileSizeCheck);

    // Create symbolic links to the log file
    auto logger = el::Loggers::getLogger("default");
    if (!logger) {
        LOG(ERROR) << "invalid logger!";
        return;
    }
    auto typedConfigurations = logger->typedConfigurations();
    if (!typedConfigurations) {
        LOG(ERROR) << "invalid typedConfigurations!";
        return;
    }
    auto logFilePath = typedConfigurations->filename(el::Level::Info);
    auto logFileName = logFilePath.substr(logFilePath.find_last_of("/") + 1);
    auto symLinkName = get_log_path() + "/" + m_module_name + ".log";
    unlink(symLinkName.c_str());
    symlink(logFileName.c_str(), symLinkName.c_str());

    if (m_netlog_host != "" && m_netlog_port > 0) {
        //network logging
        el::Helpers::installLogDispatchCallback<NetLogger>("NetLogger");
        NetLogger *nlg = el::Helpers::logDispatchCallback<NetLogger>("NetLogger");
        if (!nlg) {
            LOG(ERROR) << "invalid NetLogger!";
            return;
        }
        nlg->enable(m_netlog_host, m_netlog_port, m_module_name);
        LOG(INFO) << "Netlogger enabled.";
    }
}

bool logging::load_settings(const std::string &config_file_path)
{
    std::ifstream in_conf_file(config_file_path);
    std::string line;

    const std::string SETTING = "setting";

    if (!in_conf_file.is_open()) {
        return false;
    }

    bool in_setting_block = false;
    while (std::getline(in_conf_file, line)) {
        string_utils::trim(line);
        if (!line.empty()) {
            if (line.at(0) == '#')
                continue;
            if (line.at(0) == '[') {
                if (line.find(SETTING) != std::string::npos) {
                    in_setting_block = true;
                } else { // global
                    in_setting_block = false;
                }
                continue;
            }
            if (in_setting_block) {
                auto pos = line.find_first_of("=");
                if (pos == std::string::npos) {
                    // invalid setting, continue
                    continue;
                }
                auto log_pos = line.find("log_");
                if (0 != log_pos) {
                    // not a log setting, continue
                    continue;
                }
                m_settings[line.substr(0, pos)] = line.substr(pos + 1);
            }
        }
    }
    in_conf_file.close();
    return true;
}

bool logging::save_settings(const std::string &config_file_path)
{
    std::ofstream out_conf_file(config_file_path);

    out_conf_file << "[setting]" << std::endl;
    for (auto &setting : m_settings) {
        out_conf_file << setting.first << "=" << setting.second << std::endl;
    }
    out_conf_file.close();

    return true;
}

void logging::set_log_path(std::string log_path)
{
    if (log_path[0] == '/') {
        m_log_path = log_path;
    } else {
        m_log_path = os_utils::get_process_dir() + "/" + log_path;
    }

    if (!os_utils::make_dir(m_log_path)) {
        std::cout << "Error, can't create log directory: " << m_log_path << std::endl;
        return;
    }
}

void logging::eval_settings()
{
    // log_path
    auto setting = m_settings.find("log_path");
    if (setting != m_settings.end()) {
        auto log_path = string_utils::trimmed_substr(setting->second);
        set_log_path(log_path);
    }

    // module log filename - must be a non-path filename
    auto module_setting_name = std::string("log_") + m_module_name + std::string("_name");
    auto module_setting = m_settings.find(module_setting_name);
    if (module_setting != m_settings.end()) {
        auto filename = string_utils::trimmed_substr(module_setting->second);
        if (std::string::npos == filename.find("/")) {
            m_log_filename = filename;
        }
    }

    // log_size
    setting = m_settings.find("log_global_size");
    module_setting_name = std::string("log_") + m_module_name + std::string("_size");
    module_setting = m_settings.find(module_setting_name);
    size_t size = LOGGING_DEFAULT_MAX_SIZE;
    size_t module_size = LOGGING_DEFAULT_MAX_SIZE;
    if (setting != m_settings.end()) {
        size = strtoul(setting->second.c_str(), nullptr, 10);
    }
    if (module_setting != m_settings.end()) {
        module_size = strtoul(module_setting->second.c_str(), nullptr, 10);
    } else {
        module_size = size; // If no module specific setting, accept a global, then default
    }
    m_logfile_size = std::min(size, module_size);

    // levels
    setting = m_settings.find("log_global_levels");
    module_setting_name = std::string("log_") + m_module_name + std::string("_levels");
    module_setting = m_settings.find(module_setting_name);
    log_levels levels(LOG_LEVELS_GLOBAL_DEFAULT);
    log_levels module_levels(LOG_LEVELS_MODULE_DEFAULT);
    if (setting != m_settings.end()) {
        levels = setting->second;
    }
    if (module_setting != m_settings.end()) {
        module_levels = module_setting->second;
    }
    m_levels = levels & module_levels;

    // syslog_levels
    setting = m_settings.find("log_global_syslog_levels");
    module_setting_name = std::string("log_") + m_module_name + std::string("_syslog_levels");
    module_setting = m_settings.find(module_setting_name);
    levels = LOG_LEVELS_SYSLOG_DEFAULT;
    module_levels = LOG_LEVELS_MODULE_DEFAULT;
    if (setting != m_settings.end()) {
        levels = setting->second;
    }
    if (module_setting != m_settings.end()) {
        module_levels = module_setting->second;
    }
    m_syslog_levels = levels & module_levels;
    auto netlog_host_pair = m_settings.find("log_netlog_host");
    auto netlog_port_pair = m_settings.find("log_netlog_port");
    if (netlog_host_pair != m_settings.end() && netlog_port_pair != m_settings.end()) {
        m_netlog_host = netlog_host_pair->second;
        m_netlog_port = string_utils::stou(netlog_port_pair->second);
    }
}
