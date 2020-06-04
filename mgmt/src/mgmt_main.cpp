
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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common_logging.h"
#include "common_message.h"
#include "common_os_utils.h"
#include "common_socket.h"
#include "common_version.h"

#include "management_server.h"
#include "mgmt_thread.h"

#define REPORT_INTERVAL_MSEC 1000

using namespace imif::common;

/// Do not use this macro anywhere else
/// It should only be there in one place and easylogging++ recommends to be in the file where
/// main function is defined.
INITIALIZE_EASYLOGGINGPP

// It should only be there in one place in each executable module
INIT_IMIF_VERSION

static bool g_running = true;
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
}

bool init_logger(int argc, char *argv[], std::string log_path)
{
    s_pLogger = new (std::nothrow) imif::common::logging(false, std::string(IMIF_MGMT));
    if (s_pLogger == nullptr) {
        std::cout << "Failed allocating logger!";
        return false;
    }

    s_pLogger->set_log_path(log_path);
    s_pLogger->apply_settings();
    // log version
    LOG(INFO) << "Running " << std::string(IMIF_MGMT) << " Version " << IMIF_VERSION << " Build date " << IMIF_BUILD_DATE
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
    std::string mgmt_port = "50051";

    int opt;
    while ((opt = getopt(argc, argv, "hl:b:c:p:")) != -1) {
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
        case 'p':
            mgmt_port.assign(optarg);
            break;
        default:
            os_utils::abortExit("Unknown command!");
        }
    }

    init_signals();

    std::string module_description;
    if (imif::common::version::handle_version_query(argc, argv, module_description)) {
        exit(0);
    }

    // Setup the logger
    if (!init_logger(argc, argv, log_path)) {
        os_utils::abortExit("can't initialize logger!");
    }

    auto std_fs = os_utils::redirect_console_std();


    /////////// socket for communication between GRPC server and mgmt thread:
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        LOG(ERROR) << "pipe creation failed.";
        return 1;
    }

    std::shared_ptr<Socket> ui_socket = std::make_shared<Socket>(pipe_fds[0]);
    imif::mgmt::MgmtThread mgmt_thread(broker_path, ui_socket, s_pLogger);
    if (!mgmt_thread.start()) {
        LOG(ERROR) << "Faild to start mgmt_thread! ";
        g_running = false;
    }

    imif::mgmt::management_library_server_thread mgmt_server_thread(pipe_fds[1]);
    if (!mgmt_server_thread.start()) {
        LOG(ERROR) << "Faild to start mgmt_server_thread! ";
        g_running = false;
    }

    if (!mgmt_server_thread.start_grpc_server(mgmt_port)) {
        LOG(ERROR) << "Failed starting GRPC server!";
    }

    while (g_running) {

        if (!mgmt_thread.is_running()) {
            LOG(ERROR) << "Thread exit";
            break;
        }

        if (!mgmt_server_thread.is_running()) {
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

    mgmt_thread.stop();
    mgmt_server_thread.stop();

    LOG(DEBUG) << "Bye Bye!";

    delete s_pLogger;
    s_pLogger = nullptr;
    
    return 0;
}
