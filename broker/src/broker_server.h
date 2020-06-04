
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

#ifndef BROKER_THREAD_H
#define BROKER_THREAD_H

#include <common_socket.h>
#include <common_thread_base.h>

#include <unordered_map>
#include <unordered_set>

namespace imif {
namespace broker {

#define RX_BUFFER_SIZE 128 * 1024
class broker_server_thread : public common::thread_base {
public:
    broker_server_thread(std::string broker_uds_path);
    ~broker_server_thread();

protected:
    bool init() final;
    bool work() final;

    virtual bool handle_msg(std::shared_ptr<common::Socket> sd);
    virtual bool socket_connected(std::shared_ptr<common::SocketServer> sd);
    virtual bool socket_disconnected(std::shared_ptr<common::Socket> sd);

private:
    std::string m_broker_uds_path;
    std::shared_ptr<common::SocketServer> m_broker_socket = nullptr;
    std::shared_ptr<common::SocketServer> m_broker_socket_tcp = nullptr;
    common::SocketPoll m_socket_poll;

    std::unordered_map<int, std::unordered_set<int>> m_fd_to_opcode;
    std::unordered_map<int, std::unordered_set<int>> m_opcode_to_fd;

    uint8_t m_rx_buffer[RX_BUFFER_SIZE];
};

} // namespace broker
} // namespace imif

#endif
