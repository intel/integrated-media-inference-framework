
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

#include "../src/broker_server.h"

#include <messages/header.h>
#include <messages/proto/broker_control.pb.h>

#include <common_broker_thread.h>
#include <common_os_utils.h>

#include <easylogging++.h>

INITIALIZE_EASYLOGGINGPP

class broker_server_thread_test : public imif::broker::broker_server_thread {
public:
    broker_server_thread_test(std::string broker_uds_path) : broker_server_thread(broker_uds_path) {}

    ~broker_server_thread_test() {}

    bool error() { return error_occured; }

protected:
    bool error_occured = true;

    virtual bool handle_msg(std::shared_ptr<imif::common::Socket> sd) override
    {
        LOG(DEBUG) << "BROKER GOT MESSAGE FROM FD: " << sd->getSocketFd();

        if (broker_server_thread::handle_msg(sd) == false) {
            LOG(ERROR) << "handle_msg failed!";
            error_occured = true;
            return false;
        }

        error_occured = false;
        return true;
    }
};

class broker_socket_thread_test : public imif::common::broker_thread {
public:
    broker_socket_thread_test(const std::string &thread_name, const std::string &broker_uds_path)
        : imif::common::broker_thread(thread_name, broker_uds_path)
    {
    }

    virtual ~broker_socket_thread_test() {}

    bool error() { return error_occured; }

protected:
    bool error_occured = true;
    bool message_sent = false;

    virtual bool post_init() override
    {
        // Subscribe to the dummy message
        if (!subscribe(imif::messages::enums::Opcode::DUMMY_MESSAGE)) {
            LOG(FATAL) << "subscribe failed!";
            return false;
        }

        return true;
    }

    virtual bool after_select(bool timeout) override
    {
        if (timeout && !message_sent) {
            message_sent = true;
            LOG(DEBUG) << "Sending dummy message...";
            return send_msg(imif::messages::enums::Opcode::DUMMY_MESSAGE);
        }

        return true;
    }

    virtual bool handle_msg(std::shared_ptr<imif::common::Socket> sd, imif::messages::enums::Opcode opcode, const void *msg,
                            size_t msg_len) override
    {
        LOG(DEBUG) << "BROKER_SOCKET GOT MESSAGE - Opcode: " << opcode;

        if (opcode != imif::messages::enums::Opcode::DUMMY_MESSAGE) {
            LOG(ERROR) << "Invalid opcode = " << opcode;
            error_occured = true;
            return false;
        }

        error_occured = false;
        return true;
    }
};

int main(int argc, char *argv[])
{
    // Ignore SIGPIPE to prevent the process from crashing on IO
    // to invalid UDS sockets
    signal(SIGPIPE, SIG_IGN);

    el::Configurations defaultConf;
    defaultConf.setToDefault();
    defaultConf.setGlobally(el::ConfigurationType::Format, "%level %datetime{%H:%m:%s:%g} %fbase:%line --> %msg");
    el::Loggers::reconfigureLogger("default", defaultConf);

    std::string broker_uds_path = "imif_broker.uds";

    broker_server_thread_test broker_server_thread(broker_uds_path);
    if (!broker_server_thread.start()) {
        LOG(FATAL) << "broker_server_thread failed to start!";
        return -1;
    }

    // Sleep for 100ms
    UTILS_SLEEP_MSEC(100);

    broker_socket_thread_test broker_socket_thread1("broker_socket_thread1", broker_uds_path);
    broker_socket_thread_test broker_socket_thread2("broker_socket_thread2", broker_uds_path);
    if (!broker_socket_thread1.start() || !broker_socket_thread2.start()) {
        LOG(FATAL) << "broker_socket_thread failed to start!";
        return -1;
    }

    // Sleep for 100ms
    UTILS_SLEEP_MSEC(1000);

    if (broker_server_thread.error() || broker_socket_thread1.error() || broker_socket_thread2.error()) {
        LOG(FATAL) << "Test failed!";
        return -1;
    }

    broker_socket_thread1.stop();
    broker_socket_thread2.stop();
    broker_server_thread.stop();

    // Optional:  Delete all global objects allocated by libprotobuf.
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
