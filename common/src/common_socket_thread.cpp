
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

#include "common_socket_thread.h"
#include "easylogging++.h"
#include "common_message.h"

using namespace imif::common;

#define DEFAULT_MAX_SOCKET_CONNECTIONS 10

socket_thread::socket_thread(const std::string &unix_socket_path_, int tcp_port)
    : thread_base(), unix_socket_path(unix_socket_path_), tcp_server_port(tcp_port), unix_server_socket(nullptr),
      tcp_server_socket(nullptr), server_max_connections(DEFAULT_MAX_SOCKET_CONNECTIONS)
{
    set_select_timeout(500);
}

socket_thread::~socket_thread() { socket_cleanup(); }

void socket_thread::set_server_max_connections(int connections) { server_max_connections = connections; }

void socket_thread::socket_cleanup()
{
    if (unix_server_socket) {
        remove_socket(unix_server_socket);
        unix_server_socket->closeSocket();
        unix_server_socket.reset();
    }

    if (tcp_server_socket) {
        remove_socket(tcp_server_socket);
        tcp_server_socket->closeSocket();
        tcp_server_socket.reset();
    }
}

bool socket_thread::init()
{
    // Cleanup previously created sockets
    socket_cleanup();

    // Handle UDS socket
    if (!unix_socket_path.empty()) {
        unix_server_socket = std::make_shared<SocketServer>(unix_socket_path, server_max_connections);
        if (!unix_server_socket) {
            THREAD_LOG(FATAL) << "unix_server_socket == nullptr";
            return false;
        } 
        const auto error_msg = unix_server_socket->getError();
        if (!error_msg.empty()) {
            THREAD_LOG(FATAL) << "unix_server_socket error: " << error_msg;
            return false;
        } 
        THREAD_LOG(DEBUG) << "new SocketServer on UDS " << unix_socket_path;
    }

    // Handle TCP socket
    if (tcp_server_port > 0) {
        tcp_server_socket = std::make_shared<SocketServer>(tcp_server_port, server_max_connections);
        if (!tcp_server_socket) {
            THREAD_LOG(ERROR) << "tcp_server_socket == nullptr";
            return false;
        } 
        const auto error_msg = tcp_server_socket->getError();
        if (!error_msg.empty()) {
            THREAD_LOG(ERROR) << "tcp_server_socket error: " << error_msg;
            return false;
        } 
        THREAD_LOG(DEBUG) << "new SocketServer on TCP port " << tcp_server_port;
    }

    // Add the server sockets to the select
    if (unix_server_socket) {
        add_socket(unix_server_socket, false);
    }

    if (tcp_server_socket) {
        add_socket(tcp_server_socket, false);
    }

    return true;
}

void socket_thread::set_select_timeout(unsigned msec)
{
    struct timeval tv;
    tv.tv_sec = (msec / 1000);
    tv.tv_usec = (1000 * (msec % 1000));
    select.setTimeout(&tv);
}

bool socket_thread::socket_connected(std::shared_ptr<Socket> sd)
{
    if (!sd) {
        THREAD_LOG(ERROR) << "sd == nullptr";
        return false;
    } else {
        add_socket(sd);
    }
    return true;
}

bool socket_thread::socket_server_accept(std::shared_ptr<SocketServer> server_socket)
{
    // Accept the connection
    auto sd = server_socket->acceptConnections();
    const auto error_msg = server_socket->getError();
    if ((!sd) || (!error_msg.empty())) {
        THREAD_LOG(ERROR) << "ServerSocket Error: " << error_msg;
        return false;
    }

    // Log the connection
    if (!sd->getUdsPath().empty()) {
        THREAD_LOG(DEBUG) << "new connection on " << sd->getUdsPath() << " sd = " << uint64_t(sd.get());
    } else {
        THREAD_LOG(DEBUG) << "new connection from ip = " << sd->getPeerIP() << " port = " << sd->getPeerPort()
                          << " sd = " << uint64_t(sd.get());
    }

    // Add the accepted socket to the select
    socket_connected(sd);
    return true;
}

bool socket_thread::socket_disconnected_internal(std::shared_ptr<Socket> sd)
{
    // Dummy read for disconnected check
    uint8_t rx_buffer_tmp[4];
    ssize_t available_bytes = sd->readBytes(rx_buffer_tmp, 1, 1, true); // try to read 1 byte
    if (available_bytes > 0) {
        return false;
    } else if ((available_bytes < 0) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // In case the read operation failed due to timeout, don't close the socket
        THREAD_LOG(ERROR) << "Got event on socket but read operation timedout!! sd=" << uint64_t(sd.get());
        clear_ready(sd);
        return true;
    }

    // handle disconnection
    if (socket_disconnected(sd)) {
        sd->closeSocket();
        remove_socket(sd);
    }

    return true;
}

bool socket_thread::work()
{
    before_select();

    int sel_ret = select.selectSocket();
    if (sel_ret < 0) {
        // Do not fail for the following "errors"
        if (errno == EAGAIN || errno == EINTR) {
            THREAD_LOG(DEBUG) << "Select returned: " << strerror(errno);
            return true;
        }

        THREAD_LOG(ERROR) << "select error: " << strerror(errno);
        return false;
    }

    after_select(bool(sel_ret == 0));

    if (sel_ret == 0) {
        return true;
    }

    // Check for incoming UDS connections
    if (unix_server_socket && read_ready(unix_server_socket)) {
        clear_ready(unix_server_socket);
        if (!socket_server_accept(unix_server_socket)) {
            return false;
        }
    }

    // Check for incoming TCP connections
    if (tcp_server_socket && read_ready(tcp_server_socket)) {
        clear_ready(tcp_server_socket);
        if (!socket_server_accept(tcp_server_socket)) {
            return false;
        }
    }

    // Handle traffic on client (accepted) sockets
    int sockets_count;
    int i = 0;
    do {
        sockets_count = select.count();
        for (i = 0; i < sockets_count; i++) {
            if (read_ready(select.at(i))) {
                auto sd = select.at(i);
                if (!sd) {
                    THREAD_LOG(WARNING) << "sd at select with index i=" << int(i) << " is nullptr, skipping";
                    continue;
                }

                if (socket_disconnected_internal(sd)) {
                    break;
                }

                handle_msg(sd);
            }
        }
        // The loop should go over all the sockets. In case something break the for loop before it ended,
        // start iterating over the sockets again.
    } while (i < sockets_count);

    return true;
}
