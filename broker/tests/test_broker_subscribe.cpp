
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

#include <common_os_utils.h>

#include <easylogging++.h>

INITIALIZE_EASYLOGGINGPP

namespace imif {
namespace broker {

class broker_server_thread_test : public broker_server_thread {
public:
    broker_server_thread_test(std::string broker_uds_path) : broker_server_thread(broker_uds_path) {}

    ~broker_server_thread_test() {}

    bool error() { return error_occured; }

protected:
    bool error_occured = false;

    virtual bool handle_msg(std::shared_ptr<common::Socket> sd) override
    {
        if (broker_server_thread::handle_msg(sd) == false) {
            LOG(ERROR) << "handle_msg failed!";
            error_occured = true;
            return false;
        }

        error_occured = false;
        return true;
    }
};

} // namespace broker
} // namespace imif

int main(int argc, char *argv[])
{
    // Ignore SIGPIPE to prevent the process from crashing on IO
    // to invalid UDS sockets
    signal(SIGPIPE, SIG_IGN);

    std::string broker_uds_path = "imif_broker.uds";

    imif::broker::broker_server_thread_test broker_server_thread(broker_uds_path);
    broker_server_thread.start();

    // Sleep for 100ms
    UTILS_SLEEP_MSEC(100);

    imif::common::SocketClient sock1(broker_uds_path);

    // Invalid header
    imif::messages::sProtoHeader header;
    header.magic = 0xDEADBEEF;
    header.length = 0;
    header.opcode = int(imif::messages::enums::Opcode::BROKER_SUBSCRIBE);

    sock1.writeBytes((const uint8_t *)&header, sizeof(header));

    // Sleep for 100ms
    UTILS_SLEEP_MSEC(100);
    if (broker_server_thread.error() == false) {
        LOG(FATAL) << "Invalid header not detected!";
    }

    // Subscribe (Valid)
    imif::messages::broker_subscribe sub_msg1;
    sub_msg1.add_opcode(imif::messages::enums::Opcode::DUMMY_MESSAGE);

    header.magic = imif::messages::enums::Consts::MAGIC;
    header.length = sub_msg1.ByteSizeLong();
    header.opcode = int(imif::messages::enums::Opcode::BROKER_SUBSCRIBE);

    sock1.writeBytes((const uint8_t *)&header, sizeof(header));
    sub_msg1.SerializeToFileDescriptor(sock1.getSocketFd());

    // Sleep for 100ms
    UTILS_SLEEP_MSEC(100);
    if (broker_server_thread.error() == true) {
        LOG(FATAL) << "Subscribe failed!";
    }

    // TODO: ADD MORE TESTS

    sock1.closeSocket();

    // Optional:  Delete all global objects allocated by libprotobuf.
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
