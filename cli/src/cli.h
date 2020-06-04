#ifndef _CLI_H
#define _CLI_H

#include <common_logging.h>

#include "mgmt_lib.h"
#include "msl_streaming_lib.h"
#include <grpcpp/grpcpp.h>
#include <iomanip>
#include <iostream>
#include <regex>
#include <string>
#include <thread>

#include "common_string_utils.h"

#include <messages/proto/enums.pb.h>
#include <messages/proto/mgmt.pb.h>

#include <messages/grpc/mgmt_ext_services.grpc.pb.h>
#include <messages/proto/mgmt_ext.pb.h>

#include <replxx.hxx>
struct FileDesc;

class Cli {
public:
    Cli(std::string history_file_path, std::string history_file_name);
    ~Cli();
    void readline(std::string &line, int &should_stop);
    void add_history(const std::string &cmd);
    int execute_cmd_tokens(std::vector<std::string> &cmd_tokens);
    int execute_cmd(std::string cmd);
    bool infer(uint32_t flow_id, const std::vector<std::string> &pathnames, bool repeat, uint32_t &count_successful,
               uint32_t &count_unsuccessful);

private:
    void print_modules();
    static void add_word_suggestion(const char *word, const char *current_token, replxx::Replxx::completions_t &completions);
    static void add_word_suggestion(const std::string &word, const char *current_token, replxx::Replxx::completions_t &completions);
    static void set_terminal_to_nonblocking(bool nonblocking);
    static void sleep(uint32_t seconds_to_sleep);
    void event_dispatch(const imif::messages::mgmt_ext::Event &event);
    void result_dispatch(const imif::messages::msl::Event &event);

private:
    replxx::Replxx m_replxx;
    imif::mgmt::management_client m_client;
    std::string m_history_file;
    imif::mstream::streaming_client m_streaming_client;

    static const std::vector<std::string> command_list;
    static const std::vector<std::string> module_list;
    static const std::vector<std::string> topic_list;
    static const std::vector<std::string> addable_list;
    static const std::vector<std::string> log_levels;
    size_t m_msl_batch_size = 12; // 0 = infinite
    std::map<std::string, imif::common::eLogLevel> m_string_to_log_level;

    template <class T> static void add_glob_pattern(const std::string &pattern, std::vector<T> &completions);
    template <class T> static void add_glob_starting_with(const std::string &dir, std::vector<T> &completions);
    static bool collect_pathnames_for_infer(const std::vector<std::string> &arguments, std::vector<FileDesc> &files);
    static uint64_t make_client_context(const std::string);
    void subscribe(const int64_t wgid, const std::string topic, const bool to_file, const std::string filename = {});
    void unsubscribe(const int64_t wgid, const std::string topic, const bool to_file);
    int64_t m_wgid = -1;
    std::unordered_map<std::string, std::unordered_multimap<int64_t, std::unique_ptr<std::ofstream>>> m_subscriptions;
};

struct FileDesc {
    FileDesc() : frame_format(imif::messages::enums::FRAMEFORMAT_INVALID), frame_size_bytes(-1), height(0), width(0) {}

    FileDesc(const imif::messages::enums::FrameFormat _frame_format, const std::string _filename,
             const size_t _frame_size_bytes = 0, const size_t _height = 0, const size_t _width = 0)
        : frame_format(_frame_format), filename(_filename), frame_size_bytes(_frame_size_bytes), height(_height), width(_width)
    {
    }

    FileDesc(const FileDesc &baseline, const std::string _filename)
        : frame_format(baseline.frame_format), filename(_filename), frame_size_bytes(baseline.frame_size_bytes),
          height(baseline.height), width(baseline.width)
    {
    }

    imif::messages::enums::FrameFormat frame_format;
    std::string filename;
    size_t frame_size_bytes; // 0 = whole file
    size_t height;
    size_t width;
};

#endif
