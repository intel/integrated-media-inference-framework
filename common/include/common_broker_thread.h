
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

#ifndef _COMMON_BROKER_THREAD_H_
#define _COMMON_BROKER_THREAD_H_

#include <common_socket.h>
#include <common_thread_base.h>

// Protobuf messages
#include "../include/messages/header.h"
#include <messages/proto/broker_control.pb.h>

// System
#include <list>
#include <memory>
#include <string>

std::ostream &operator<<(std::ostream &os, const google::protobuf::Message &proto);
std::ostream &operator<<(std::ostream &os, const std::shared_ptr<google::protobuf::Message> &proto);

namespace imif {
namespace common {

class broker_thread : public thread_base {
public:
    broker_thread(const std::string &thread_name, const std::string &broker_uds_path = std::string(),
                  std::string host = "127.0.0.1", int broker_tcp_port = 0);
    virtual ~broker_thread();

    static bool send_msg(std::shared_ptr<imif::common::Socket> socket, uint32_t opcode,
                         const google::protobuf::Message *msg = nullptr);
    static bool send_msg(std::shared_ptr<imif::common::Socket> socket, uint32_t opcode, const google::protobuf::Message &msg);

    static size_t get_free_send_buffer_size(std::shared_ptr<imif::common::Socket> socket);

protected:
    virtual bool init() final;
    virtual bool work() final;

    virtual bool post_init() { return true; }
    virtual bool before_select() { return true; }
    virtual bool after_select(bool timeout) { return true; }

    void set_select_timeout(uint timeout) { m_socket_poll.set_timeout(timeout); }

    virtual bool add_socket(std::shared_ptr<Socket> s, bool edge_trigger = false)
    {
        return m_socket_poll.add_socket(s, (edge_trigger ? uint32_t(EPOLLET) : 0));
    }
    virtual bool del_socket(std::shared_ptr<Socket> s) { return m_socket_poll.del_socket(s); }

    bool socket_server_accept(std::shared_ptr<SocketServer> &server_socket);
    virtual bool socket_connected(std::shared_ptr<common::Socket> sd);
    virtual bool socket_disconnected(std::shared_ptr<common::Socket> sd);
    virtual bool socket_error(std::shared_ptr<common::Socket> sd) { return true; };

    bool subscribe(messages::enums::Opcode opcode);
    bool subscribe(const std::list<messages::enums::Opcode> &opcodes_list);
    bool subscribe(std::shared_ptr<imif::common::Socket> sd, messages::enums::Opcode opcode);
    bool subscribe(std::shared_ptr<imif::common::Socket> sd, const std::list<messages::enums::Opcode> &opcodes_list);

    bool unsubscribe(messages::enums::Opcode opcode);
    bool unsubscribe(const std::list<messages::enums::Opcode> &opcodes_list);

    int read_proto_message(std::shared_ptr<imif::common::Socket> socket, messages::sProtoHeader &header, uint8_t *buff,
                           int buff_len);

    bool send_msg(messages::enums::Opcode opcode, const google::protobuf::Message &msg);
    bool send_msg(messages::enums::Opcode opcode, const google::protobuf::Message *msg = nullptr);

    size_t get_free_send_buffer_size();

    virtual bool handle_msg(std::shared_ptr<Socket> sd, messages::enums::Opcode opcode, const void *msg, size_t msg_len)
    {
        return true;
    }
    virtual bool handle_msg(std::shared_ptr<Socket> sd) { return true; }

    uint8_t m_rx_buffer[128 * 1024];
    uint32_t m_module_id = 0;

private:
    std::string m_broker_uds_path;
    std::shared_ptr<SocketClient> m_broker_socket = nullptr;

    int m_broker_tcp_port;
    std::string m_broker_tcp_host;
    std::shared_ptr<SocketClient> m_broker_tcp_socket = nullptr;

    SocketPoll m_socket_poll;
};

} // namespace common
} // namespace imif

#endif // _COMMON_BROKER_THREAD_H_
