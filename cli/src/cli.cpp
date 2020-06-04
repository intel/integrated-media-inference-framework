#include "cli.h"

#include "common_broker_thread.h"
#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <sys/types.h>
#include <termio.h>
#include <unistd.h>

#include <experimental/filesystem>

#include <messages/proto/mgmt.pb.h>
#include <messages/proto/types.pb.h>

using replxx::Replxx;
using namespace imif;

namespace fs = std::experimental::filesystem;

const std::vector<std::string> Cli::command_list = {
    "help",        "connect", "ping", "disconnect", "enable", "disable", "list",  "subscribe", "unsubscribe", "add",  "remove",
    "setloglevel", "reset",   "msl",  "start",      "load",   "sleep",   "setwg", "namewg",    "renamewg",    "push", "pull"};

const std::vector<std::string> Cli::module_list = {"all", "mgmt", "mstream", "inference", "mdecode"};
const std::vector<std::string> Cli::addable_list = {"flow", "source", "config", "workgroup"};
const std::vector<std::string> Cli::log_levels = {"info", "debug", "error", "fatal", "trace", "warning"};

///// some service functions...
void str_toupper(std::string &s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
}

imif::common::eLogLevel parse_log_level(std::string log_level)
{
    str_toupper(log_level);
    if (!log_level.compare("INFO")) {
        return imif::common::eLogLevel::LOG_LEVEL_INFO;
    } else if (!log_level.compare("DEBUG")) {
        return imif::common::eLogLevel::LOG_LEVEL_DEBUG;
    } else if (!log_level.compare("ERROR")) {
        return imif::common::eLogLevel::LOG_LEVEL_ERROR;
    } else if (!log_level.compare("FATAL")) {
        return imif::common::eLogLevel::LOG_LEVEL_FATAL;
    } else if (!log_level.compare("TRACE")) {
        return imif::common::eLogLevel::LOG_LEVEL_TRACE;
    } else if (!log_level.compare("WARNING")) {
        return imif::common::eLogLevel::LOG_LEVEL_WARNING;
    } else if (!log_level.compare("ALL")) {
        return imif::common::eLogLevel::LOG_LEVEL_ALL;
    } else {
        LOG(ERROR) << "failed to parse log level: " << log_level;
        return imif::common::eLogLevel::LOG_LEVEL_NONE;
    }
}
static bool s_quit = false;
Replxx::ACTION_RESULT set_quit(char32_t code)
{
    s_quit = true;
    return Replxx::ACTION_RESULT::RETURN; // CONTINUE, RETURN, BAIL
}

Cli::Cli(std::string history_file_path, std::string history_file_name)
{
    m_replxx.install_window_change_handler();

    if (fs::exists(history_file_path)) {
        m_history_file = fs::path(history_file_path).append(history_file_name).generic_string();
        m_replxx.history_load(m_history_file.c_str());
    } else {
        m_history_file.clear();
    }

    m_replxx.set_max_history_size(256);
    m_replxx.set_max_hint_rows(3);
    m_replxx.set_word_break_characters(" \t");

    m_replxx.bind_key(Replxx::KEY::control('C'), set_quit);

    m_replxx.set_completion_callback([this](const std::string &edit_buffer,
                                            int &last_token_length) -> replxx::Replxx::completions_t {
        replxx::Replxx::completions_t completions;
        std::string buff_plus_space(edit_buffer);
        buff_plus_space += ' ';
        std::vector<std::string> cmd_tokens = imif::common::string_utils::str_split(buff_plus_space, ' ');

        if (cmd_tokens.size() > 1) {
            std::string previous_token = cmd_tokens[cmd_tokens.size() - 2];
            std::string previous_previous_token;
            if (cmd_tokens.size() > 2) {
                previous_previous_token = cmd_tokens[cmd_tokens.size() - 3];
            }
            const char *current_token = (cmd_tokens[cmd_tokens.size() - 1]).c_str();
            if (!previous_token.compare("enable") || !previous_token.compare("disable") || !previous_token.compare("reset")) {
                for (const auto &module : module_list) {
                    if (strncmp(current_token, module.c_str(), strlen(current_token)) == 0) {
                        completions.emplace_back(module);
                    }
                }
                return completions;
            } else if (!previous_token.compare("add") || !previous_token.compare("remove")) {
                for (const auto &addable : addable_list) {
                    add_word_suggestion(addable, current_token, completions);
                }
                return completions;
            } else if (!cmd_tokens[0].compare("setloglevel")) {
                add_word_suggestion("all", current_token, completions);
                for (const auto &module : module_list) {
                    add_word_suggestion(module, current_token, completions);
                }
                for (const auto &log_level : log_levels) {
                    add_word_suggestion(log_level, current_token, completions);
                }

                return completions;
            } else if ((cmd_tokens.size() == 2) &&
                       ((!cmd_tokens[0].compare("subscribe")) || (!cmd_tokens[0].compare("unsubscribe")))) {
                imif::messages::mgmt_ext::AllModulesStatus all_modules_status;
                m_client.get_module_list(&all_modules_status);
                for (int i = 0; i < all_modules_status.topic_size(); ++i) {
                    add_word_suggestion(all_modules_status.topic(i), current_token, completions);
                }
                return completions;
            } else if ((cmd_tokens.size() == 3) &&
                       ((!cmd_tokens[0].compare("subscribe")) || (!cmd_tokens[0].compare("unsubscribe")))) {
                for (const auto &w : {"cli", "file"}) {
                    add_word_suggestion(w, current_token, completions);
                }
                return completions;
            } else if (!previous_token.compare("msl")) {
                for (const auto &w : {"batch-size", "connect", "disconnect", "infer", "ping", "subscribe", "unsubscribe",
                                      "start_stream", "stop_stream"}) {
                    add_word_suggestion(w, current_token, completions);
                }
                return completions;
            } else if ((cmd_tokens.size() == 3) && !(cmd_tokens[0].compare("msl")) && !(cmd_tokens[1].compare("start_stream"))) {
                add_glob_starting_with(cmd_tokens[cmd_tokens.size() - 1], completions);
            } else if ((cmd_tokens.size() == 3) && !(cmd_tokens[0].compare("msl")) && !(cmd_tokens[1].compare("infer"))) {
                for (const auto &w : {"once", "repeat"}) {
                    add_word_suggestion(w, current_token, completions);
                }
                return completions;
            } else if (!previous_token.compare("load")) {
                add_glob_starting_with(cmd_tokens[cmd_tokens.size() - 1], completions);
            } else if ((cmd_tokens.size() >= 5) && !(cmd_tokens[0].compare("msl")) && !(cmd_tokens[1].compare("infer")) &&
                       (previous_token.compare("-rgb")) && (previous_previous_token.compare("-rgb"))) {
                add_glob_starting_with(cmd_tokens[cmd_tokens.size() - 1], completions);
                add_word_suggestion("-rgb", current_token, completions);
            } else if (!cmd_tokens[0].compare("list")) {
                for (const auto &addable : addable_list) {
                    add_word_suggestion(addable, current_token, completions);
                }
            } else if (!cmd_tokens[0].compare("push")) {
                if (cmd_tokens.size() < 3) {
                    add_glob_starting_with(cmd_tokens[cmd_tokens.size() - 1], completions);
                } else {
                    imif::messages::mgmt_ext::AllModulesStatus all_modules_status;
                    m_client.get_module_list(&all_modules_status);
                    for (int i = 0; i < all_modules_status.topic_size(); ++i) {
                        add_word_suggestion(all_modules_status.topic(i), current_token, completions);
                    }
                }
            } else if (!cmd_tokens[0].compare("pull")) {
                imif::messages::mgmt_ext::AllModulesStatus all_modules_status;
                m_client.get_module_list(&all_modules_status);
                for (int i = 0; i < all_modules_status.topic_size(); ++i) {
                    add_word_suggestion(all_modules_status.topic(i), current_token, completions);
                }
            }
        }
        // below is all we need for completion without subcommands
        for (const auto &command : command_list) {
            if (!edit_buffer.compare(0, edit_buffer.size(), command, 0, edit_buffer.size())) {
                completions.emplace_back(command);
            }
        }
        return completions;
    });

    for (const auto &log_level : log_levels) {
        m_string_to_log_level.insert(std::make_pair(log_level, parse_log_level(log_level)));
    }

    m_client.register_listener_callback(std::bind(&Cli::event_dispatch, this, std::placeholders::_1));
    m_streaming_client.register_listener_callback(std::bind(&Cli::result_dispatch, this, std::placeholders::_1));
}

Cli::~Cli()
{
    if (!m_history_file.empty()) {
        m_replxx.history_save(m_history_file.c_str());
    }
}

void Cli::readline(std::string &line, int &should_stop)
{
    line.clear();
    char const *linep;
    std::string prompt;
    if (m_wgid < 0) {
        prompt = "wg: all >";
    } else {
        prompt = "wg: " + std::to_string(m_wgid) + " >";
    }
    linep = m_replxx.input(prompt);
    if (linep) {
        line = linep;
    } else {
        LOG(INFO) << "Caught termination signal, exiting";
        should_stop = 1;
        return;
    }
    should_stop = s_quit;
}

void Cli::add_history(const std::string &cmd)
{
    if (!m_history_file.empty()) {
        m_replxx.history_add(cmd);
    }
}

void Cli::print_modules()
{
    imif::messages::mgmt_ext::AllModulesStatus all_modules_status;
    m_client.get_module_list(&all_modules_status);
    for (int i = 0; i < all_modules_status.module_status_size(); ++i) {
        auto &item = all_modules_status.module_status(i);
        LOG(INFO) << "wg: " << item.wgid() << " module: " << item.module_name() << " is "
                  << (item.registered() ? "registered" : "unregistered") << " and " << (item.enabled() ? "enabled" : "disabled");
    }
}

void Cli::add_word_suggestion(const char *word, const char *current_token, Replxx::completions_t &completions)
{
    if (strncmp(current_token, word, strlen(current_token)) == 0) {
        completions.emplace_back(word);
    }
}

void Cli::add_word_suggestion(const std::string &word, const char *current_token, Replxx::completions_t &completions)
{
    if (strncmp(current_token, word.c_str(), strlen(current_token)) == 0) {
        completions.emplace_back(word);
    }
}

void Cli::event_dispatch(const imif::messages::mgmt_ext::Event &event)
{
    bool printed = false;
    std::string topic = event.module_name();
    for (auto iter = m_subscriptions.find(topic); iter != m_subscriptions.end(); ++iter) {
        for (auto wgid : std::list<int64_t>{-1, event.wgid()}) {
            for (auto iter2 = iter->second.find(wgid); iter2 != iter->second.end(); ++iter2) {
                auto &pofstream = iter2->second;
                if (pofstream) {
                    *pofstream << event.message() << "\n";
                } else {
                    if (!printed) {
                        LOG(INFO) << "Got event from " << topic << ": " << event.message();
                        printed = true;
                    }
                }
            }
        }
    }
}

void Cli::result_dispatch(const imif::messages::msl::Event &event)
{
    auto flow_id = event.flow_id();
    LOG(INFO) << "Got event from flow_id = " << flow_id << ": " << event.message();
}

int Cli::execute_cmd_tokens(std::vector<std::string> &cmd_tokens)
// Return value:
//   Negative - Error, quit CLI
//   0 - OK
//   Positive - Quit CLI intentionally
{
    std::string rest_of_cmd;
    for (size_t i = 1; i < cmd_tokens.size(); ++i) {
        rest_of_cmd += cmd_tokens[i];
        rest_of_cmd += ' ';
    }
    if (!cmd_tokens[0].compare("connect")) {
        std::string host_or_ip_str, port_str;
        if (cmd_tokens.size() < 2 || cmd_tokens[1].length() == 0) {
            host_or_ip_str = "localhost";
            port_str = "50051";
        } else {
            auto split_pos = rest_of_cmd.find(':');
            if (split_pos == std::string::npos) {
                LOG(ERROR) << "invalid connection string, it doesn't even contain a \":\"!";
                return 0;
            }
            host_or_ip_str = rest_of_cmd.substr(0, split_pos);
            port_str = rest_of_cmd.substr(split_pos + 1);
        }
        LOG(INFO) << "connecting using ip: " << host_or_ip_str << " port: " << port_str;
        if (!m_client.connect(host_or_ip_str, port_str)) {
            LOG(INFO) << "Connection failed!\n";
            return 0;
        }
    } else if (!cmd_tokens[0].compare("disconnect")) {
        m_client.disconnect();
    } else if (!cmd_tokens[0].compare("enable")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify which module";
        } else if (std::find(module_list.begin(), module_list.end(), cmd_tokens[1]) == module_list.end()) {
            LOG(INFO) << cmd_tokens[1] << " is not a valid module";
            return 0;
        }
        std::string sub_module;
        if (cmd_tokens.size() == 3) {
            sub_module = cmd_tokens[2];
        }
        m_client.set_module_state(cmd_tokens[1], true, m_wgid, sub_module);
    } else if (!cmd_tokens[0].compare("disable")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify which module";
        } else if (std::find(module_list.begin(), module_list.end(), cmd_tokens[1]) == module_list.end()) {
            LOG(INFO) << cmd_tokens[1] << " is not a valid module";
            return 0;
        }

        std::string sub_module = "";
        if (cmd_tokens.size() == 3) {
            sub_module = cmd_tokens[2];
        }
        m_client.set_module_state(cmd_tokens[1], false, m_wgid, sub_module);
    } else if (!cmd_tokens[0].compare("add")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify what to add" << std::endl;
        }
        if (!cmd_tokens[1].compare("workgroup")) {
            std::string host_or_ip_str, port_str, wgname = "";
            if (cmd_tokens.size() > 3) {
                wgname = cmd_tokens[3];
            }
            if (cmd_tokens.size() < 3 || cmd_tokens[2].length() == 0) {
                LOG(ERROR) << "url:port needed to add workgroup";
                return 0;
            } else {
                auto split_pos = cmd_tokens[2].find(':');
                if (split_pos == std::string::npos) {
                    LOG(ERROR) << "invalid connection string, it doesn't even contain a \":\"!";
                    return 0;
                }
                host_or_ip_str = cmd_tokens[2].substr(0, split_pos);
                port_str = cmd_tokens[2].substr(split_pos + 1);
            }
            LOG(INFO) << "adding workgroup ip: " << host_or_ip_str << " port: " << port_str;
            uint32_t port;
            try {
                port = common::string_utils::stou(port_str);
            } catch (std::exception e) {
                LOG(ERROR) << "bad port string " << e.what();
                return 0;
            }
            auto wgid = m_client.add_workgroup(host_or_ip_str, port, wgname);
            if (wgid < 0) {
                LOG(INFO) << "Failed connecting to workgroup!\n";
                return 0;
            }
            LOG(INFO) << "Connected to workgroup: " << wgid;
            m_wgid = wgid;
        } else {
            LOG(INFO) << "Adding " << cmd_tokens[1] << " not implemented" << std::endl;
        }
    } else if (!cmd_tokens[0].compare("remove")) {
        if (cmd_tokens.size() < 3) {
            LOG(INFO) << "Specify what to remove, i.e. remove source <source_id>" << std::endl;
            return 0;
        }
        try {
            if (!cmd_tokens[1].compare("source")) {
                uint32_t source_id = common::string_utils::stou(cmd_tokens[2]);
                m_client.remove_source(source_id, m_wgid);
            } else if (!cmd_tokens[1].compare("flow")) {
                uint32_t flow_id = common::string_utils::stou(cmd_tokens[2]);
                m_client.remove_flow(flow_id, m_wgid);
            } else if (!cmd_tokens[1].compare("config")) {
                if (cmd_tokens.size() <= 3) {
                    LOG(INFO) << "remove config requires config name and id, i.e. remove config mdecode 1";
                    return 0;
                }
                uint32_t cfg_id = common::string_utils::stou(cmd_tokens[3]);
                m_client.remove_config(cfg_id, cmd_tokens[2], m_wgid);
            } else {
                LOG(INFO) << "Removing " << cmd_tokens[1] << " not implemented" << std::endl;
            }
        } catch (std::exception e) {
            LOG(INFO) << "Must have a number as " << cmd_tokens[1] << "_id, instead got: " << cmd_tokens[2] << " " << e.what() << std::endl;
        }
    } else if (!cmd_tokens[0].compare("list")) {
        if (cmd_tokens.size() <= 1) {
            print_modules();
        } else {
            if (!cmd_tokens[1].compare("modules")) {
                print_modules();
            } else {
                std::string what = "";
                int id = -1;
                if (cmd_tokens.size() >= 3) {
                    if (!std::isdigit(cmd_tokens[2][0])) {
                        what = cmd_tokens[2];
                        if (cmd_tokens.size() >= 4) {
                            id = common::string_utils::stou(cmd_tokens[3]);
                        }
                    } else {
                        id = common::string_utils::stou(cmd_tokens[2]);
                    }
                }
                imif::messages::mgmt_ext::ListResponse list_response;
                if (id < 0) {
                    m_client.list(cmd_tokens[1], what, &list_response, m_wgid);
                } else {
                    m_client.list(cmd_tokens[1], what, id, &list_response, m_wgid);
                }
                for (const auto &list_item : list_response.list_item()) {
                    LOG(INFO) << list_item;
                }
            }
        }

    } else if (!cmd_tokens[0].compare("ping")) {
        if (m_client.ping()) {
            LOG(INFO) << "pong";
        } else {
            LOG(INFO) << "No response!";
        }
    } else if (!cmd_tokens[0].compare("subscribe")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify which topic";
            return 0;
        }
        std::string topic = cmd_tokens[1];
        bool to_file;
        std::string filename;
        if ((cmd_tokens.size() < 3) || ((cmd_tokens.size() == 3) && !cmd_tokens[2].compare("cli"))) {
            to_file = false;
            filename = {};
        } else {
            if (!cmd_tokens[2].compare("file")) {
                if (cmd_tokens.size() < 4) {
                    LOG(INFO) << "Missing filename";
                    return 0;
                } else if (cmd_tokens.size() > 4) {
                    LOG(INFO) << "Too many operands";
                    return 0;
                }
                to_file = true;
                filename = cmd_tokens[3];
            } else {
                LOG(INFO) << "Expected the word cli or file. The word " << cmd_tokens[2] << " is not valid here.";
                return 0;
            }
        }
        LOG(INFO) << "Subscribing to topic: " << topic;
        subscribe(m_wgid, topic, to_file, filename);
    } else if (!cmd_tokens[0].compare("unsubscribe")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify which topic";
            return 0;
        }
        std::string topic = cmd_tokens[1];
        bool to_file;
        if ((cmd_tokens.size() < 3) || ((cmd_tokens.size() == 3) && !cmd_tokens[2].compare("cli"))) {
            to_file = false;
        } else if (cmd_tokens.size() > 3) {
            LOG(INFO) << "Too many operands";
            return 0;
        } else if (!cmd_tokens[2].compare("file")) {
            to_file = true;
        } else {
            LOG(INFO) << "Expected the word cli or file. The word " << cmd_tokens[2] << " is not valid here.";
            return 0;
        }

        LOG(INFO) << "Unsubscribing to topic: " << topic;
        unsubscribe(m_wgid, topic, to_file);
    } else if (!cmd_tokens[0].compare("setloglevel")) {
        imif::common::eLogLevel log_level = imif::common::eLogLevel::LOG_LEVEL_NONE;
        unsigned int word_index = 0;
        if (++word_index >= cmd_tokens.size()) {
            LOG(ERROR) << "Not enough arguments to setloglevel";
            return 0;
        }

        bool enable = true;
        std::string module_name = cmd_tokens[word_index];
        if (std::find(module_list.begin(), module_list.end(), module_name) == module_list.end()) {
            LOG(INFO) << "Unknown module: " << module_name;
            return 0;
        }

        if (++word_index >= cmd_tokens.size()) {
            LOG(ERROR) << "Not enough arguments to setloglevel";
            return 0;
        }

        std::map<std::string, imif::common::eLogLevel>::iterator it;
        if (!cmd_tokens[word_index].compare("all")) {
            log_level = imif::common::eLogLevel::LOG_LEVEL_ALL;
        } else if ((it = m_string_to_log_level.find(cmd_tokens[word_index])) != m_string_to_log_level.end()) {
            log_level = it->second;
        } else {
            LOG(INFO) << "Invalid log level: " << cmd_tokens[word_index];
            return 0;
        }

        if (++word_index < cmd_tokens.size()) {
            if (!cmd_tokens[word_index].compare("1")) {
                enable = true;
            } else if (!cmd_tokens[word_index].compare("0")) {
                enable = false;
            } else {
                LOG(ERROR) << "unrecognized token: " << cmd_tokens[word_index];
                return 0;
            }
        }

        LOG(INFO) << (enable ? "Enabling log levels" : "Disabling log levels");
        m_client.set_log_level(module_name, log_level, enable);
    } else if (!cmd_tokens[0].compare("reset")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Specify which module";
        } else if (std::find(module_list.begin(), module_list.end(), cmd_tokens[1]) == module_list.end()) {
            LOG(INFO) << cmd_tokens[1] << " is not a valid module";
            return 0;
        }
        m_client.send_reset(cmd_tokens[1], m_wgid);
    } else if (!cmd_tokens[0].compare("start")) {
        uint32_t source_id;
        try {
            source_id = common::string_utils::stou(cmd_tokens[1]);
        } catch (std::exception e) {
            LOG(INFO) << "Expected an unsigned number, but got " << cmd_tokens[1] << " instead. " << e.what();
            return false;
        }
        m_client.start_source(source_id, m_wgid);
    } else if (!cmd_tokens[0].compare("load")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Please specify .yaml config file to load.";
            return 0;
        }
        m_client.load_yaml(cmd_tokens[1], m_wgid);
    } else if (!cmd_tokens[0].compare("sleep")) {
        if (cmd_tokens.size() != 2) {
            LOG(INFO) << "Please specify how many seconds to sleep.";
            return 0;
        }
        uint32_t seconds_to_sleep;
        try {
            seconds_to_sleep = common::string_utils::stou(cmd_tokens[1]);
        } catch (std::exception e) {
            LOG(INFO) << "Expected an unsigned number, but got " << cmd_tokens[1] << " instead. " << e.what();
            return false;
        }
        sleep(seconds_to_sleep);
    } else if (!cmd_tokens[0].compare("setwg")) {
        if (cmd_tokens.size() != 2) {
            LOG(INFO) << "Please specify which workgroup to set.";
            return 0;
        }
        if (cmd_tokens[1] == "all") {
            m_wgid = -1;
            return 0;
        }
        if (std::isdigit(cmd_tokens[1][0])) {
            try {
                m_wgid = std::stoi(cmd_tokens[1]);
            } catch (std::exception e) {
                LOG(INFO) << "Expected an unsigned number, but got " << cmd_tokens[1] << " instead. " << e.what();
                return false;
            }
        } else {
            auto wgid = m_client.get_workgroup_id(cmd_tokens[1]);
            if (wgid >= 0) {
                m_wgid = wgid;
                return 0;
            } else {
                LOG(INFO) << "Unknown workgroup: " << cmd_tokens[1];
                return false;
            }
        }
    } else if (!cmd_tokens[0].compare("namewg")) {
        if (cmd_tokens.size() < 3) {
            LOG(INFO) << "Syntax: namewg <wgid> <wg_name>";
            return 0;
        }
        int64_t wgid;
        try {
            wgid = std::stoi(cmd_tokens[1]);
        } catch (std::exception e) {
            LOG(INFO) << "Expected an unsigned number, but got " << cmd_tokens[1] << " instead. " << e.what();
            return false;
        }
        m_client.set_workgroup_name(wgid, cmd_tokens[2]);
    } else if (!cmd_tokens[0].compare("renamewg")) {
        if (cmd_tokens.size() < 3) {
            LOG(INFO) << "Syntax: renamewg <old wg_name> <new wg_name>";
            return 0;
        }
        auto wgid = m_client.get_workgroup_id(cmd_tokens[1]);
        if (wgid < 0) {
            LOG(INFO) << "Unknown workgroup: " << cmd_tokens[1];
            return 0;
        }
        m_client.set_workgroup_name(wgid, cmd_tokens[2]);
    } else if (!cmd_tokens[0].compare("msl")) {
        if (cmd_tokens.size() < 2) {
            LOG(INFO) << "Command incomplete." << std::endl;
            return false;
        } else if (!cmd_tokens[1].compare("batch-size")) {
            if (cmd_tokens.size() == 3) {
                int batch_size;
                try {
                    batch_size = common::string_utils::stou(cmd_tokens[2]);
                } catch (std::exception e) {
                    LOG(INFO) << "Expected a number, but got " << cmd_tokens[2] << " instead. " << e.what();
                    return false;
                }
                if (batch_size < 0) {
                    LOG(INFO) << "batch-size must be 0 or positive.";
                }
                m_msl_batch_size = batch_size;
            }
            if (m_msl_batch_size == 0) {
                LOG(INFO) << "MSL batch size is: Infinite (bound by message size only)";
            } else {
                LOG(INFO) << "MSL batch size is: " << m_msl_batch_size;
            }
        } else if (!cmd_tokens[1].compare("connect")) {
            std::string connection_string, host_or_ip_str, port_str;
            if (cmd_tokens.size() < 3) {
                connection_string = "localhost:";
            } else {
                connection_string = cmd_tokens[2];
            }
            auto split_pos = connection_string.find(':');
            if (split_pos == std::string::npos) {
                LOG(ERROR) << "invalid connection string '" << connection_string << "', it doesn't even contain a \":\"!";
                return false;
            }
            host_or_ip_str = connection_string.substr(0, split_pos);
            port_str = connection_string.substr(split_pos + 1);

            LOG(INFO) << "connecting streaming library using ip: " << host_or_ip_str << " port: " << port_str;
            if (!m_streaming_client.connect(host_or_ip_str, port_str)) {
                LOG(INFO) << "Connection failed!\n";
                return false;
            }
            LOG(INFO) << "connecting streaming library successful. Our Client ID is " << m_streaming_client.get_client_id();
        } else if (!cmd_tokens[1].compare("disconnect")) {
            LOG(INFO) << "Disconnecting\n";
            m_streaming_client.disconnect();
        } else if (!cmd_tokens[1].compare("ping")) {
            auto status = m_streaming_client.is_connected();
            LOG(INFO) << "MSL " << (status ? "Connected" : "not connected") << std::endl;
        } else if (!cmd_tokens[1].compare("infer")) {
            if (cmd_tokens.size() < 5) {
                LOG(INFO) << "Command incomplete." << std::endl;
                return false;
            }
            bool repeat;
            if (!cmd_tokens[2].compare("once")) {
                repeat = false;
            } else if (!cmd_tokens[2].compare("repeat")) {
                repeat = true;
            } else {
                LOG(INFO) << "Expected 'once' or 'repeat', but got " << cmd_tokens[2] << " instead.";
                return false;
            }
            uint32_t flow_id;
            try {
                flow_id = common::string_utils::stou(cmd_tokens[3]);
            } catch (std::exception e) {
                LOG(INFO) << "Expected a number, but got " << cmd_tokens[3] << " instead. " << e.what();
                return false;
            }
            uint32_t num_successful = 0;
            uint32_t num_unsuccessful = 0;

            auto pathnames = std::vector<std::string>(cmd_tokens.begin() + 4, cmd_tokens.end());

            if (infer(flow_id, pathnames, repeat, num_successful, num_unsuccessful)) {
                LOG(INFO) << "Aborted.";
                return false;
            }
            LOG(INFO) << "Successfully sent " << num_successful << " frames.";
            LOG(INFO) << "Failed to send " << num_unsuccessful << " frames.";
            return false;
        } else if (!cmd_tokens[1].compare("subscribe") || !cmd_tokens[1].compare("unsubscribe")) {
            bool subscribe = !cmd_tokens[1].compare("subscribe");
            uint32_t flow_id = 0;
            if (cmd_tokens.size() < 3) {
                LOG(INFO) << "Command incomplete: specify flow id to subscribe to" << std::endl;
                return false;
            }
            int32_t stage_id = -1;
            if (cmd_tokens.size() > 3) {
                try {
                    stage_id = common::string_utils::stou(cmd_tokens[3]);
                } catch (std::exception e) {
                    LOG(INFO) << "Expected a number, but got " << cmd_tokens[3] << " instead. " << e.what();
                    return false;
                }
            }
            try {
                flow_id = common::string_utils::stou(cmd_tokens[2]);
            } catch (std::exception e) {
                LOG(INFO) << "Expected a number, but got " << cmd_tokens[2] << " instead. " << e.what();
                return false;
            }
            if (!m_streaming_client.subscribe(flow_id, stage_id, subscribe)) {
                LOG(INFO) << "Aborted.";
                return false;
            }
            return false;
        } else if (!cmd_tokens[1].compare("start_stream")) {
            if (cmd_tokens.size() < 4) {
                LOG(INFO) << "Command incomplete. example use:" << std::endl;
                LOG(INFO) << "msl start_stream file.h264 10 <max_mbps>";
                return false;
            }

            uint32_t flow_id = 0;
            try {
                flow_id = common::string_utils::stou(cmd_tokens[3]);
            } catch (std::exception e) {
                LOG(INFO) << "Expected a number, but got " << cmd_tokens[3] << " instead. " << e.what();
                return false;
            }

            float max_rate = 0;
            if (cmd_tokens.size() > 4) {
                try {
                    max_rate = std::stof(cmd_tokens[4]);
                } catch (std::exception e) {
                    LOG(INFO) << "Expected a number, but got " << cmd_tokens[4] << " instead. " << e.what();
                    return false;
                }
            }
            if (!m_streaming_client.start_stream_file(cmd_tokens[2], flow_id, max_rate)) {
                LOG(INFO) << "Aborted.";
                return false;
            }
            return false;
        } else if (!cmd_tokens[1].compare("stop_stream")) {
            if (cmd_tokens.size() < 3) {
                LOG(INFO) << "Command incomplete: expecting flow id." << std::endl;
                return false;
            }

            uint32_t flow_id = 0;
            try {
                flow_id = common::string_utils::stou(cmd_tokens[2]);
            } catch (std::exception e) {
                LOG(INFO) << "Expected a number, but got " << cmd_tokens[3] << " instead. " << e.what();
                return false;
            }
            if (!m_streaming_client.stop_stream_file(flow_id)) {
                LOG(INFO) << "Aborted.";
                return false;
            }
            return false;
        } else {
            LOG(INFO) << "Unrecognized: " << cmd_tokens[1] << std::endl;
            return false;
        }
    } else if (!cmd_tokens[0].compare("push")) {
        if (cmd_tokens.size() < 4) {
            LOG(INFO) << "Command incomplete: Usage: push <filename> <module> <wgid>" << std::endl;
            return false;
        }
        int64_t wgid;
        try {
            wgid = std::stoi(cmd_tokens[3]);
        } catch (std::exception e) {
            wgid = m_client.get_workgroup_id(cmd_tokens[3]);
            if (wgid == -1) {
                LOG(INFO) << "Unrecognized workgroup: " << cmd_tokens[3];
                return false;
            }
        }
        m_client.push(cmd_tokens[1], cmd_tokens[2], wgid);
    } else if (!cmd_tokens[0].compare("pull")) {
        if (cmd_tokens.size() < 3) {
            LOG(INFO) << "Command incomplete: Usage: pull <module> <wgid>" << std::endl;
            return false;
        }
        int64_t wgid;
        try {
            wgid = std::stoi(cmd_tokens[2]);
        } catch (std::exception e) {
            wgid = m_client.get_workgroup_id(cmd_tokens[2]);
            if (wgid == -1) {
                LOG(INFO) << "Unrecognized workgroup: " << cmd_tokens[2];
                return false;
            }
        }
        m_client.pull(cmd_tokens[1], wgid);
    } else if (!cmd_tokens[0].compare("help")) {
        LOG(INFO) << "Command list:";
        LOG(INFO) << "\t connect";
        LOG(INFO) << "\t disconnect";
        LOG(INFO) << "\t load <yaml config file>";
        LOG(INFO) << "\t enable <all or module name>";
        LOG(INFO) << "\t disable <all or module name>";
        LOG(INFO) << "\t start <source id>" << std::endl << "\t     - start source stream";
        LOG(INFO) << "\t subscribe <module> cli" << std::endl << "\t     - subscribe to events of the module on screen";
        LOG(INFO) << "\t subscribe <module> file <filename>" << std::endl << "\t     - save events of the module to file";
        LOG(INFO) << "\t unsubscribe <module> [cli/file]" << std::endl << "\t     - stops subscription";
        LOG(INFO) << "\t setloglevel <module/all> <level/all> [0/1]" << std::endl
                  << "\t     - set the module to log loglevel events (1 default), or to stop logging such events (0)" << std::endl
                  << "\t     - level is one of: info, debug, error, fatal, trace, warning";
        LOG(INFO) << "\t list [flow/source/config/modules] [module] [id]" << std::endl
                  << "\t     - lists flows/sources/configuration and output relevant parameters" << std::endl;
        LOG(INFO) << "\t remove [flow/source/config] [module] [id]" << std::endl
                  << "\t     - removes a flow/source/configuration" << std::endl;
        LOG(INFO) << "\t setwg [workgroup_id / workgroup_name]" << std::endl << "\t     - set the current workgroup";
        LOG(INFO) << "\t namewg <workgroup_id> <workgroup_name>" << std::endl << "\t     - name the workgroup";
        LOG(INFO) << "\t renamewg <old workgroup_name> <new workgroup_name>" << std::endl << "\t     - rename the workgroup";
        LOG(INFO) << "\t push <filename> <module name> <workgroup_id/name>" << std::endl;
        LOG(INFO) << "\t pull <module name> <workgroup_id/name>" << std::endl;
        LOG(INFO) << "\t msl batch-size <n> - 0 for unlimited";
        LOG(INFO) << "\t msl connect";
        LOG(INFO) << "\t msl disconnect";
        LOG(INFO) << "\t msl infer [once|repeat] <flow_id> [-rgb <width> <height>] <path> ...";
        LOG(INFO) << "\t msl subscribe <flow_id>";
        LOG(INFO) << "\t msl unsubscribe <flow_id>";
        LOG(INFO) << "\t msl ping";
        LOG(INFO) << "\t msl start_stream <file_name> <flow_id> [max_mbps]";
        LOG(INFO) << "\t msl stop_stream <flow_id>";
        LOG(INFO) << "\t sleep [seconds]";

        LOG(INFO) << "\t reset <all or module name> - resets state, removing all sources and flows.";
    } else if ((!cmd_tokens[0].compare("exit")) || (!cmd_tokens[0].compare("quit"))) {
        return 1;
    } else {
        LOG(INFO) << "Invalid command " << cmd_tokens[0] << std::endl;
    }
    return 0;
}

int Cli::execute_cmd(std::string cmd)
{
    std::vector<std::string> cmd_tokens = imif::common::string_utils::str_split(cmd, ' ');
    return execute_cmd_tokens(cmd_tokens);
}

bool Cli::collect_pathnames_for_infer(const std::vector<std::string> &arguments, std::vector<FileDesc> &files)
{
    static FileDesc file_desc;
    for (auto iter = arguments.cbegin(); iter != arguments.cend(); ++iter) {
        auto arg = *iter;
        if (arg == "-rgb") {
            int width = 0;
            int height = 0;
            if (++iter != arguments.cend()) {
                width = std::atoi(iter->c_str());
                if (++iter != arguments.cend()) {
                    height = std::atoi(iter->c_str());
                }
            }
            if (width <= 0 || height <= 0 || width > 9999 || height > 9999) {
                LOG(ERROR) << "Incorrect format. use -rgb <height> <width>. For example -rgb 1920 1080";
                return true;
            }
            file_desc = FileDesc(imif::messages::enums::RGB, "", height * width * 3, height, width);
            continue;
        } else if (fs::is_directory(arg)) {
            std::vector<std::string> pathnames;
            add_glob_starting_with(arg, pathnames);
            collect_pathnames_for_infer(pathnames, files);
        } else {
            std::vector<std::string> patterns;
            add_glob_pattern(arg, patterns);
            for (auto &filename : patterns) {
                if (fs::is_regular_file(filename)) {
                    if (std::regex_search(filename, std::regex("[.](jpg|jpeg)$", std::regex_constants::icase))) {
                        files.push_back(FileDesc(imif::messages::enums::JPEG, filename));
                        continue;
                    }

                    if (std::regex_search(filename, std::regex("[.](rgb|bin)$", std::regex_constants::icase))) {
                        if (file_desc.frame_format != imif::messages::enums::RGB) {
                            LOG(ERROR) << "Skipping file " << filename << " because it is not following an -rgb directive.";
                            continue;
                        }
                        files.push_back(FileDesc(file_desc, filename));
                        continue;
                    }

                    LOG(INFO) << "Skipping filename with unrecognized extension: " << filename;
                    continue;
                }

                if (errno == ENOENT) {
                    LOG(INFO) << "Filename does not exist; Skipping " << filename;
                    continue;
                }

                if (errno) {
                    LOG(ERROR) << "Can\'t access " << filename << " - " << strerror(errno);
                    return true;
                }
            }
        }
    }
    return false;
}

bool Cli::infer(uint32_t flow_id, const std::vector<std::string> &arguments, bool repeat, uint32_t &count_successful,
                uint32_t &count_unsuccessful)
{
    std::vector<FileDesc> filedescs;
    if (collect_pathnames_for_infer(arguments, filedescs))
        return true;

    if (filedescs.size() == 0) {
        LOG(ERROR) << "No files to process.";
        return false;
    }

    uint32_t count_messages = 0;
    bool anything_sent = false;
    bool done = false;

    set_terminal_to_nonblocking(true);

    std::ifstream ifs;

    imif::messages::msl::InferResponse response;
    std::string *ppayload = nullptr;
    uint64_t client_context = 8088;
    size_t _width = 0;
    size_t _height = 0;
    size_t _frame_size_bytes = 0;
    std::string _filename;

    imif::messages::enums::FrameFormat _frame_format = imif::messages::enums::FRAMEFORMAT_INVALID;

    auto start_time = std::chrono::steady_clock::now();
    auto next_statistics_display_time = start_time + std::chrono::seconds(2);
    auto iter_filedesc = filedescs.begin();
    while (!done) {
        imif::messages::types::FramesData frames_data;
        frames_data.Clear();
        imif::messages::enums::FrameFormat frame_format = imif::messages::enums::FRAMEFORMAT_INVALID;
        while (!done) {
            if (!ppayload && (!ifs.is_open() || ifs.eof())) {
                if (iter_filedesc == filedescs.end()) {
                    if (!repeat) {
                        done = true;
                        break;
                    }
                    if (!anything_sent) {
                        LOG(WARNING) << "No valid messages created.";
                        done = true;
                        break;
                    }
                    iter_filedesc = filedescs.begin();
                }
                _filename = iter_filedesc->filename;
                _frame_size_bytes = iter_filedesc->frame_size_bytes;
                _width = iter_filedesc->width;
                _height = iter_filedesc->height;
                _frame_format = iter_filedesc->frame_format;

                ifs = std::ifstream(_filename, std::ifstream::binary);
                client_context = make_client_context(_filename);
                if (_frame_size_bytes != 0)
                    client_context *= 100000;
            }

            if ((frame_format != imif::messages::enums::FRAMEFORMAT_INVALID) && (frame_format != _frame_format)) {
                // Cannot mix frame formats in same message
                break;
            }
            frame_format = _frame_format;

            if ((m_msl_batch_size > 0) && (frames_data.frame_data_size() >= (int)m_msl_batch_size)) {
                break;
            }

            if (!ppayload) {
                if (_frame_size_bytes == 0) {
                    // Treat the whole file as a single frame
                    ppayload = new std::string(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
                    ifs.close();
                    ++iter_filedesc;
                } else {
                    // Treat each segment of length _frame_size_bytes as a frame
                    ppayload = new std::string();
                    ppayload->resize(_frame_size_bytes);
                    ifs.read(&((*ppayload)[0]), _frame_size_bytes);
                    size_t bytes_read = ifs.gcount();

                    if (bytes_read != _frame_size_bytes) {
                        if (bytes_read != 0) {
                            LOG(WARNING) << "Ignoring the last " << bytes_read << " bytes of " << _filename
                                         << " because expected frame size is " << _frame_size_bytes;
                        }
                        delete ppayload;
                        ppayload = nullptr;
                        ifs.close();
                        ++iter_filedesc;
                        break;
                    }
                    ++client_context;
                }
            }
            if (!ppayload) {
                LOG(ERROR) << "Unable to allocate memory";
                return true;
            }
            if (ppayload->size() + 1024 >= m_streaming_client.max_message_size) {
                LOG(INFO) << "Frame too large to be delivered - Skipping";
                delete ppayload;
                ppayload = nullptr;
            } else {
                if ((frames_data.ByteSizeLong() + ppayload->size() + 1024) >= m_streaming_client.max_message_size) {
                    // Frame too large to be added to current message
                    break;
                }

                imif::messages::types::FrameData *frame_data = frames_data.add_frame_data();
                frame_data->set_client_context(client_context);
                frame_data->set_allocated_payload(ppayload);

                if (_height > 0) {
                    frame_data->set_height(_height);
                    frame_data->set_width(_width);
                }
                anything_sent = true;
                ppayload = nullptr;
            }
        }

        if (frames_data.frame_data_size() > 0)
        {
            auto status = m_streaming_client.infer(flow_id, frame_format, frames_data, response);
            count_messages++;

            if (status) {
                for (auto frame_status : response.frame_infer_response()) {
                    if (frame_status.ok()) {
                        count_successful++;
                    } else {
                        count_unsuccessful++;
                    }
                }
            } else {
                count_unsuccessful += frames_data.frame_data_size();
            }
        }
        auto now = std::chrono::steady_clock::now();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        auto seconds = milliseconds / 1000;

        if (now > next_statistics_display_time) {
            next_statistics_display_time = now + std::chrono::seconds(2);

            std::ostringstream statistics;
            if (seconds > 0) {
                statistics << std::setw(10) << std::right << count_successful / seconds << " fps; " << count_unsuccessful / seconds
                           << " failed fps over " << seconds << " seconds.";
            }

            LOG(INFO) << "Sent " << std::setw(7) << std::right << count_messages << " messages. " << count_successful
                      << " frames successfully ;  " << count_unsuccessful << " failed. " << statistics.str()
                      << (repeat ? " Hit any key to stop." : "");
            char c;
            if (read(0, &c, 1) > 0) {
                done = true;
            }
        }
    }

    set_terminal_to_nonblocking(false);

    if (ppayload) {
        delete ppayload;
        ppayload = nullptr;
    }
    return false;
}

uint64_t Cli::make_client_context(const std::string s)
{
    try {
        int start;
        auto end = s.find_last_of("0123456789");
        if (end == std::string::npos)
            return 0;
        auto prev = s.find_last_not_of("0123456789", end);
        if (prev == std::string::npos) {
            start = 0;
        } else {
            start = prev + 1;
        }
        return std::stoll(s.substr(start, end - start + 1));
    } catch (const std::invalid_argument &) {
        return 0;
    } catch (const std::out_of_range &) {
        return 0;
    }
}

template <class T> void Cli::add_glob_starting_with(const std::string &dir, std::vector<T> &completions)
{
    add_glob_pattern(dir + "*", completions);
}

template <class T> void Cli::add_glob_pattern(const std::string &pattern, std::vector<T> &completions)
{
    glob_t glob_bfr;

    if (!glob(pattern.c_str(), GLOB_MARK | GLOB_TILDE, NULL, &glob_bfr)) {
        for (size_t i = 0; glob_bfr.gl_pathv[i]; i++)
            completions.emplace_back((glob_bfr.gl_pathv[i]));
        globfree(&glob_bfr);
    }
}

void Cli::set_terminal_to_nonblocking(bool nonblocking)
{
    struct termios t;
    tcgetattr(0, &t);
    if (nonblocking)
        t.c_lflag &= ~ICANON;
    else
        t.c_lflag |= ICANON;
    tcsetattr(0, TCSANOW, &t);
    int fl = fcntl(0, F_GETFL);
    if (nonblocking)
        fl |= int(O_NONBLOCK);
    else
        fl &= ~int(O_NONBLOCK);
    fcntl(0, F_SETFL, fl);
}

void Cli::sleep(uint32_t seconds_to_sleep)
{
    while (seconds_to_sleep > 0) {
        LOG(INFO) << "(CLI sleeping for " << seconds_to_sleep << " seconds...)";
        auto secs = seconds_to_sleep > 60 ? 60 : seconds_to_sleep;
        std::this_thread::sleep_for(std::chrono::seconds(secs));
        seconds_to_sleep -= secs;
    }
}

void Cli::subscribe(const int64_t wgid, const std::string topic, const bool to_file, const std::string filename)
{
    std::unique_ptr<std::ofstream> pofstream = nullptr;

    if (to_file) {
        pofstream = std::unique_ptr<std::ofstream>(new std::ofstream(filename, std::ofstream::out | std::ofstream::trunc));
        if (!pofstream) {
            LOG(FATAL) << "Failed allocating!";
            return;
        }

        if (!pofstream->is_open()) {
            LOG(ERROR) << "Unable to open " << filename;
            return;
        }
    } else {
        pofstream = nullptr;
    }

    m_subscriptions[topic].emplace(wgid, std::move(pofstream));

    m_client.subscribe(topic, true, wgid);
}

void Cli::unsubscribe(const int64_t wgid, const std::string topic, const bool to_file)
{
    bool is_last_subscription = true;
    for (auto iter = m_subscriptions.find(topic); iter != m_subscriptions.end(); ++iter) {
        for (auto iter2 = iter->second.find(wgid); iter2 != iter->second.end();) {
            auto &pofstream = iter2->second;
            if (!!pofstream == to_file) {
                iter->second.erase(iter2++);
            } else {
                is_last_subscription = false;
                iter2++;
            }
        }
    }

    if (is_last_subscription) {
        m_client.subscribe(topic, false, wgid);
    }
}
