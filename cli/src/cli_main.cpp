#include <common_logging.h>
#include <common_os_utils.h>
#include <common_version.h>

#include "cli.h"

/// Do not use this macro anywhere else
/// It should only be there in one place and easylogging++ recommends to be in the file where
/// main function is defined.
INITIALIZE_EASYLOGGINGPP

// It should only be there in one place in each executable module
INIT_IMIF_VERSION

static void init_logger()
{
    el::Configurations defaultConf;

    defaultConf.setToDefault();
    //defaultConf.setGlobally(el::ConfigurationType::Format,"%level %datetime{%H:%m:%s} %fbase %line --> %msg");
    defaultConf.setGlobally(el::ConfigurationType::Format, "%msg");
    defaultConf.setGlobally(el::ConfigurationType::ToFile, "false");
    defaultConf.setGlobally(el::ConfigurationType::ToStandardOutput, "true");
    el::Loggers::reconfigureAllLoggers(defaultConf);
}

static int s_signal = 0;

static void init_signals()
{
    // Signal handler function
    auto signal_handler = [](int signum) { s_signal = signum; };

    struct sigaction sigterm_action;
    sigterm_action.sa_handler = signal_handler;
    sigemptyset(&sigterm_action.sa_mask);
    sigterm_action.sa_flags = 0;
    sigaction(SIGTERM, &sigterm_action, NULL);

    struct sigaction sigint_action;
    sigint_action.sa_handler = signal_handler;
    sigemptyset(&sigint_action.sa_mask);
    sigint_action.sa_flags = 0;
    sigaction(SIGINT, &sigint_action, NULL);

    struct sigaction sigusr1_action;
    sigusr1_action.sa_handler = signal_handler;
    sigemptyset(&sigusr1_action.sa_mask);
    sigusr1_action.sa_flags = 0;
    sigaction(SIGUSR1, &sigusr1_action, NULL);
}

int main(int argc, char **argv)
{
    int should_stop = 0;

    init_logger();
    init_signals();
    LOG(INFO) << "IMIF CLI, Type \"help\" for list of commands" << std::endl << std::endl;

    Cli cli("../temp", "imif_cli.history");

    cli.execute_cmd("connect");

    if (argc >= 2) {
        //split multiple commands
        std::string cmd_line;
        for (int i = 1; i < argc; i++) {
            if (i > 1)
                cmd_line += " ";
            cmd_line += std::string(argv[i]);
        }
        auto cmd_vector = imif::common::string_utils::str_split(cmd_line, ',');
        // execute all commands
        for (auto &cmd : cmd_vector) {
            imif::common::string_utils::trim(cmd);
            LOG(INFO) << "Executing: " << cmd;
            auto cmd_tokens = imif::common::string_utils::str_split(cmd, ' ');
            should_stop = cli.execute_cmd_tokens(cmd_tokens);
        }
    }

    while (should_stop == 0) {
        std::string cmd;
        cli.readline(cmd, should_stop);
        if (cmd.length() == 0 || should_stop != 0) {
            continue;
        }
        cli.add_history(cmd);

        auto sts = cli.execute_cmd(cmd);
        if (sts < 0) {
            LOG(INFO) << "Exit by error." << std::endl;
            break;
        } else if (sts > 0) {
            LOG(INFO) << "Exit by command." << std::endl;
            break;
        }
    }

    return 0;
}
