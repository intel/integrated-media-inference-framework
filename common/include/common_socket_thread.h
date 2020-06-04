
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

#ifndef _COMMON_SOCKET_THREAD_H_
#define _COMMON_SOCKET_THREAD_H_

#include "common_thread_base.h"
// #include "message_structs.h"
#include "common_defines.h"
#include "common_socket.h"

#define DEFAULT_SELECT_TIMEOUT_MS 500

namespace imif {
namespace common {

class socket_thread : public thread_base {
public:
    socket_thread(const std::string &unix_socket_path_ = std::string(), int tcp_port = 0);
    virtual ~socket_thread();
    void set_server_max_connections(int connections);
    virtual void set_select_timeout(unsigned msec);

    virtual bool init() override;
    virtual bool work() override;

protected:
    virtual bool handle_msg(std::shared_ptr<Socket> sd) = 0;
    virtual void before_select() {}
    virtual void after_select(bool timeout) {}
    virtual bool socket_connected(std::shared_ptr<Socket> sd);
    virtual bool socket_disconnected(std::shared_ptr<Socket> sd) = 0;

    virtual void add_socket(std::shared_ptr<Socket> sd, bool add_to_vector = true) { select.addSocket(sd); }
    virtual void remove_socket(std::shared_ptr<Socket> sd) { select.removeSocket(sd); }
    inline void clear_ready(std::shared_ptr<Socket> sd) { select.clearReady(sd); }
    virtual bool read_ready(std::shared_ptr<Socket> sd) { return select.readReady(sd); }

private:
    void socket_cleanup();
    bool socket_server_accept(std::shared_ptr<SocketServer> server_socket);
    bool socket_disconnected_internal(std::shared_ptr<Socket> sd);

    std::string unix_socket_path;
    int tcp_server_port;

    std::shared_ptr<SocketServer> unix_server_socket = nullptr;
    std::shared_ptr<SocketServer> tcp_server_socket = nullptr;

    std::vector<std::shared_ptr<Socket>> sockets;

    ///////////////////////////////////////////////

    int server_max_connections;
    SocketSelect select;
};

} // namespace common
} // namespace imif

#endif //_COMMON_SOCKET_THREAD_H_
