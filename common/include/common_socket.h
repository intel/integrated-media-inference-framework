
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

#ifndef _COMMON_SOCKET_H
#define _COMMON_SOCKET_H

#include <arpa/inet.h>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

namespace imif {
namespace common {

class Socket {
public:
    Socket(SOCKET s, long readTimeout = 1000);
    Socket(SOCKET s, std::string peer_ip, int port_port, long readTimeout = 1000);
    Socket(const std::string &uds_path = std::string(), long readTimeout = 1000);
    virtual ~Socket();

    enum SocketMode { SocketModeBlocking, SocketModeNonBlocking };

    size_t getBytesReady();
    size_t getBytesWritePending();
    ssize_t getBufferLength(bool tx = true);
    bool setBufferLength(size_t buffer_size, bool tx = true);
    static size_t sGetBytesWritePending(SOCKET fd);
    static ssize_t sGetBufferLength(SOCKET fd, bool tx = true);

    ssize_t readBytes(uint8_t *buf, size_t buf_size, size_t buf_len = 0, bool isPeek = false, bool isBlocking = false);
    ssize_t writeBytes(const uint8_t *buf, size_t buf_len);
    ssize_t writeBytes(const uint8_t *buf, size_t buf_len, int port, struct sockaddr_in addr_in = {});
    ssize_t writeString(std::string msg) { return writeBytes((const uint8_t *)msg.c_str(), (size_t)msg.length()); }

    bool setWriteTimeout(long msec);
    bool setReadTimeout(long msec);
    void closeSocket();
    bool isOpen();

    SOCKET getSocketFd() { return m_socket; }
    std::string getError()
    {
        std::string error = m_error;
        m_error.clear();
        return error;
    }
    std::string getPeerIP() { return m_peer_ip; }
    int getPeerPort() { return m_peer_port; }
    std::string getUdsPath() { return m_uds_path; }
    void setPeerMac(std::string mac) { m_peer_mac = mac; }
    std::string getPeerMac() { return m_peer_mac; }
    bool isAcceptedSocket() { return m_accepted_socket; }
    void setIsServer() { m_is_server = true; }

protected:
    friend class SocketServer;
    friend class SocketSelect;
    SOCKET m_socket = INVALID_SOCKET;
    std::string m_error = "";
    std::string m_peer_ip = "";
    std::string m_uds_path = "";
    int m_peer_port = 0;
    std::string m_peer_mac;
    bool m_accepted_socket = false;
    bool m_external_handler = false;
    bool m_is_server = false;
};

class SocketClient : public Socket {
public:
    SocketClient(const std::string &uds_path, long readTimeout = 1000);
    SocketClient(const std::string &host, int port, int connect_timeout_msec = -1, long readTimeout = 1000);
};

class SocketServer : public Socket {
public:
    SocketServer() {}
    SocketServer(const std::string &uds_path, int connections, SocketMode mode = SocketModeBlocking, fs::perms prms = fs::perms::owner_read | fs::perms::owner_write);
    SocketServer(int port, int connections, std::string ip_str = "127.0.0.1", SocketMode mode = SocketModeBlocking);
    std::shared_ptr<Socket> acceptConnections();
};

class SocketSelect {
public:
    SocketSelect();
    ~SocketSelect();
    void setTimeout(timeval *tval);
    void addSocket(std::shared_ptr<Socket> sd);
    void removeSocket(std::shared_ptr<Socket> sd);
    void clearReady(std::shared_ptr<Socket> sd);
    std::shared_ptr<Socket> at(size_t idx);
    int selectSocket();
    bool readReady(std::shared_ptr<Socket> sd);
    bool readReady(size_t idx);
    int count() { return (int)m_socketVec.size(); }
    bool isBlocking() { return m_isBlocking; }
    std::string getError()
    {
        return m_error;
        m_error.clear();
    }

private:
    bool m_isBlocking;
    std::vector<std::shared_ptr<Socket>> m_socketVec;
    fd_set m_socketSet;
    timeval *m_socketTval;
    std::string m_error = "";
};

class SocketPoll {

public:
    // Socket handlers type
    typedef const std::function<bool(std::shared_ptr<Socket>)> socket_handler_t;

public:
    // Default poll timeout is 500ms
    SocketPoll(uint timeout = 500);
    ~SocketPoll();

    bool add_socket(std::shared_ptr<Socket> socket, uint32_t additional_flags = 0);
    bool del_socket(std::shared_ptr<Socket> socket);

    // @retval -1 - Error
    // @retval  0 - Timeout
    // @retval  n - Processed sockets
    int poll(socket_handler_t data_handler, socket_handler_t error_handler = {}, socket_handler_t disconnect_handler = {});

    // Number of sockets in the poll
    int size() const { return m_sockets_map.size(); }

    void set_timeout(uint timeout) { m_timeout = timeout; }

private:
    int m_epoll_fd;
    uint m_timeout;
    std::unordered_map<int, std::shared_ptr<Socket>> m_sockets_map;
};

} // namespace common
} // namespace imif

#endif //__SOCKET_H
