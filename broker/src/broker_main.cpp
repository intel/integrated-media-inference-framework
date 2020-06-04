
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

#include "broker_server.h"

// IMIF Common
#include "common_logging.h"
#include "common_os_utils.h"
#include "common_version.h"

// Do not use this macro anywhere else
// It should only be there in one place and easylogging++ recommends to be in the file where
// main function is defined.
INITIALIZE_EASYLOGGINGPP

// It should only be there in one place in each executable module
INIT_IMIF_VERSION

static bool g_running = false;
static int s_signal = 0;

// Pointer to logger instance
static imif::common::logging *s_pLogger = nullptr;

static void handle_signal()
{
    if (!s_signal)
        return;
    switch (s_signal) {
    // Terminate
    case SIGTERM:
    case SIGINT: {
        LOG(INFO) << "Caught signal '" << strsignal(s_signal) << "' Exiting...";
        g_running = false;
        break;
    }
    default: {
        LOG(WARNING) << "Unhandled Signal: '" << strsignal(s_signal) << "' Ignoring...";
        break;
    }
    }
    s_signal = 0;
}

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

    // Ignore SIGPIPE to prevent the process from crashing on IO
    // to invalid UDS sockets
    signal(SIGPIPE, SIG_IGN);
}

bool init_logger(int argc, char *argv[], std::string log_path)
{
    s_pLogger = new (std::nothrow) imif::common::logging(false, std::string(IMIF_BRK));
    if (s_pLogger == nullptr) {
        std::cout << "Failed allocating logger!";
        return false;
    }

    s_pLogger->set_log_path(log_path);
    s_pLogger->apply_settings();
    // log version
    LOG(INFO) << "Running " << std::string(IMIF_BRK) << " Version " << IMIF_VERSION << " Build date " << IMIF_BUILD_DATE
              << std::endl
              << std::endl;
    imif::common::version::log_version(argc, argv);
    return true;
}

int main(int argc, char *argv[])
{
    std::string log_path = "../logs/";
    std::string broker_path = "../temp/imif_broker";
    std::string conf_file = "../config/config.yaml";

    int opt;
    while ((opt = getopt(argc, argv, "hl:b:c:")) != -1) {
        switch (opt) {
        case 'l':
            log_path.assign(optarg);
            break;
        case 'b':
            broker_path.assign(optarg);
            break;
        case 'c':
            conf_file.assign(optarg);
            break;
        default:
            std::cout << "Unknown command!\n";
            exit(0);
        }
    }

    // Register signals
    init_signals();

    // Process version
    if (imif::common::version::handle_version_query(argc, argv)) {
        exit(0);
    }

    // Initialize the logger
    if (!init_logger(argc, argv, log_path)) {
        imif::common::os_utils::abortExit("Failed initializing the logger!");
    }

    auto std_fs = imif::common::os_utils::redirect_console_std();


    // Create the Broker UDS folder
    std::size_t found = broker_path.find_last_of("/\\");
    if (found != std::string::npos) {
        imif::common::os_utils::make_dir(broker_path.substr(0, found));
    }

    // Start the broker thread
    imif::broker::broker_server_thread broker_server_thread(broker_path);
    if (!broker_server_thread.start("broker_server_thread")) {
        imif::common::os_utils::abortExit("Failed starting the broker thread!");
    } else {
        g_running = true;
    }

    while (g_running) {

        if (!broker_server_thread.is_running()) {
            LOG(ERROR) << "Thread exit";
            break;
        }

        // Handle signals
        if (s_signal) {
            handle_signal();
            continue;
        }

        UTILS_SLEEP_MSEC(500);
    }

    // Stop the thread
    broker_server_thread.stop();

    LOG(INFO) << "Exiting...";

    delete s_pLogger;
    s_pLogger = nullptr;

    return 0;
}
