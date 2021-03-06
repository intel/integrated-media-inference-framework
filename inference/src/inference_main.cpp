
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

#include <signal.h>
#include <sstream>

#include "common_logging.h"
#include "common_os_utils.h"
#include "common_version.h"
#include "inference_thread.h"

#include "easylogging++.h"

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
    s_pLogger = new (std::nothrow) imif::common::logging(false, std::string(IMIF_INFERENCE));
    if (s_pLogger == nullptr) {
        std::cout << "Failed allocating logger!";
        return false;
    }

    s_pLogger->set_log_path(log_path);
    s_pLogger->apply_settings();
    // log version
    LOG(INFO) << "Running " << std::string(IMIF_INFERENCE) << " Version " << IMIF_VERSION << " Build date " << IMIF_BUILD_DATE
              << std::endl
              << std::endl;
    imif::common::version::log_version(argc, argv);
    return true;
}

int main(int argc, char *argv[])
{
    std::string log_path = "../logs/";
    std::string broker_path = "../temp/imif_broker";

    int opt;
    while ((opt = getopt(argc, argv, "hl:b:")) != -1) {
        switch (opt) {
        case 'l':
            log_path.assign(optarg);
            break;
        case 'b':
            broker_path.assign(optarg);
            break;
        default:
            os_utils::abortExit("Unknown command!");
        }
    }

    init_signals();

    std::string module_description;
    if (imif::common::version::handle_version_query(argc, argv, module_description)) {
        return 0;
    }

    // Setup the logger
    if (!init_logger(argc, argv, log_path)) {
        os_utils::abortExit("can't initialize logger!");
    }

    auto std_fs = os_utils::redirect_console_std();


    // create the worker thread per device (temporary - hard coded two devices. need to make it spawn threads dynamically)
    imif::inference::InferenceThread inference_thread(broker_path, s_pLogger);
    if (!inference_thread.start()) {
        LOG(ERROR) << "unable to start inference_thread thread! ";
        g_running = false;
    }

    while (g_running) {

        if (!inference_thread.is_running()) {
            LOG(ERROR) << "ilb_thread Thread0 exit";
            break;
        }

        // Handle signals
        if (s_signal) {
            handle_signal();
            continue;
        }
        UTILS_SLEEP_MSEC(500);
    }

    inference_thread.stop();

    LOG(DEBUG) << "Bye Bye!";
    delete s_pLogger;
    s_pLogger = nullptr;

    exit(0);
}
