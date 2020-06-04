
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

#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "easylogging++.h"
#include "common_socket.h"
#include "common_string_utils.h"

using namespace imif::common;

Socket::Socket(const std::string &uds_path, long readTimeout)
{
    m_error.clear();
    m_peer_mac.clear();
    m_uds_path = uds_path;
    if (!uds_path.empty()) {
        m_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    } else {
        m_socket = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (m_socket == INVALID_SOCKET) {
        m_error = uds_path + " -> socket() failed";
    }

    if (readTimeout != 0)
        setReadTimeout(readTimeout);
}

Socket::Socket(SOCKET s, long readTimeout)
{
    m_error.clear();
    m_peer_mac.clear();
    m_socket = s;
    m_external_handler = true;

    if (readTimeout != 0)
        setReadTimeout(readTimeout);
}

Socket::Socket(SOCKET s, std::string peer_ip, int port_port, long readTimeout)
{
    m_error.clear();
    m_peer_mac.clear();
    m_socket = s;
    m_peer_ip = peer_ip;
    m_peer_port = port_port;

    if (readTimeout != 0)
        setReadTimeout(readTimeout);
}

Socket::~Socket()
{
    if (m_external_handler)
        return;
    closeSocket();
    if (m_is_server && (!m_uds_path.empty())) {
        remove(m_uds_path.c_str());
    }
}

bool Socket::setWriteTimeout(long msec)
{
    if (m_socket == INVALID_SOCKET) {
        return false;
    }
    timeval tval;
    tval.tv_sec = 0;
    tval.tv_usec = 1000 * msec;
    if (setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tval, sizeof(timeval)) < 0) {
        return false;
    }
    return true;
}

bool Socket::setReadTimeout(long msec)
{
    if (m_socket == INVALID_SOCKET) {
        return false;
    }

    long sec = 0;
    long usec = 0;
    if (msec == 0) {
        sec = (msec / 1000);
        usec = (msec % 1000) * 1000;
    }

    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = usec;
    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv) < 0) {
        return false;
    }

    return true;
}

void Socket::closeSocket()
{
    if ((m_socket != INVALID_SOCKET) && ((!m_external_handler) || (m_accepted_socket))) {
        close(m_socket);
        m_socket = INVALID_SOCKET;
    }
}

bool Socket::isOpen() { return (m_socket != INVALID_SOCKET); }

size_t Socket::getBytesReady()
{
    u_long cnt = 0;
    if (m_socket != INVALID_SOCKET) {
        ioctl(m_socket, FIONREAD, &cnt);
    }
    return (size_t)cnt;
}

size_t Socket::getBytesWritePending()
{
    if (m_socket == INVALID_SOCKET)
        return 0;

    return sGetBytesWritePending(m_socket);
}

ssize_t Socket::getBufferLength(bool tx)
{
    if (m_socket == INVALID_SOCKET)
        return 0;

    return sGetBufferLength(m_socket, tx);
}

bool Socket::setBufferLength(size_t buffer_size, bool tx)
{
    if (m_socket == INVALID_SOCKET)
        return false;
    socklen_t optlen = sizeof(int);
    int optval = (int)buffer_size;
    if (setsockopt(m_socket, SOL_SOCKET, tx ? SO_SNDBUF : SO_RCVBUF, (int *)&optval, optlen) < 0) {
        return false;
    }
    return true;
}

ssize_t Socket::sGetBufferLength(SOCKET fd, bool tx)
{
    if (fd == INVALID_SOCKET)
        return 0;
    socklen_t optlen = sizeof(int);
    int optval;
    if (getsockopt(fd, SOL_SOCKET, tx ? SO_SNDBUF : SO_RCVBUF, (int *)&optval, &optlen) < 0) {
        return -1;
    }
    return ((ssize_t)optval);
}

size_t Socket::sGetBytesWritePending(SOCKET fd)
{
    int pending = 0;
    ioctl(fd, SIOCOUTQ, &pending);
    return (size_t)pending;
}

ssize_t Socket::readBytes(uint8_t *buf, size_t buf_size, size_t buf_len, bool isPeek, bool isBlocking)
{
    if (m_socket == INVALID_SOCKET) {
        return 0;
    }

    ssize_t len = 0;
    if (buf_len == 0) {
        return 0;
    }

    if (buf_len > buf_size) {
        LOG(WARNING) << "message truncated, buffer too small!!! buf_size=" << buf_size << " buf_len=" << buf_len;
        buf_len = buf_size;
    }
    int flags = isPeek ? MSG_PEEK : 0;
    flags |= isBlocking ? int(MSG_WAITALL) : 0;
    len = recv(m_socket, (char *)buf, (int)buf_len, flags);

    if (len < 0) {
        LOG(ERROR) << "Error reading from socket (" << m_socket << "): " << strerror(errno);
    }

    return len;
}

ssize_t Socket::writeBytes(const uint8_t *buf, size_t buf_len)
{
    if (m_socket == INVALID_SOCKET) {
        return 0;
    }
    int flags = MSG_NOSIGNAL;
    return send(m_socket, (const char *)buf, (int)buf_len, flags);
}

ssize_t Socket::writeBytes(const uint8_t *buf, size_t buf_len, int port, struct sockaddr_in addr_in)
{
    if (m_socket == INVALID_SOCKET) {
        return 0;
    }
    return sendto(m_socket, (const char *)buf, (int)buf_len, 0, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

SocketServer::SocketServer(const std::string &uds_path, int connections, SocketMode mode, fs::perms prms)
{
    // Server socket is always internally managed
    m_external_handler = false;

    sockaddr_un addr;
    m_uds_path = uds_path;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    imif::common::string_utils::copy_string(addr.sun_path, uds_path.c_str(), sizeof(addr.sun_path));
    m_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_socket == INVALID_SOCKET) {
        m_error = std::string("can't open unix socket");
        return;
    }

    if (mode == SocketModeNonBlocking) {
        u_long arg = 1;
        ioctl(m_socket, FIONBIO, &arg);
    }

    setIsServer();
    remove(uds_path.c_str());

    if (bind(m_socket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        close(m_socket);
        m_socket = INVALID_SOCKET;
        m_error = "bind() to " + uds_path + " failed, error: " + strerror(errno);
        return;
    }

    try {
        fs::permissions(addr.sun_path, prms);
    } catch (const fs::filesystem_error& e) {
        m_error = std::string("can't chmod unix socket: ") + e.what();
        return;
    }

    listen(m_socket, connections);
}

SocketServer::SocketServer(int port, int connections, std::string ip_str, SocketMode mode)
{
    sockaddr_in addr;

    // Server socket is always internally managed
    m_external_handler = false;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; // windows --> PF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_str.c_str());
    addr.sin_port = htons(port);
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket == INVALID_SOCKET) {
        return;
    }

    int enable_b = 1;
    int *enable = &enable_b;
    if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, enable, sizeof(enable)) < 0) {
        close(m_socket);
        m_socket = INVALID_SOCKET;
        return;
    }

    setIsServer();

    if (mode == SocketModeNonBlocking) {
        u_long arg = 1;
        ioctl(m_socket, FIONBIO, &arg);
    }
    if (bind(m_socket, (sockaddr *)&addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
        close(m_socket);
        m_socket = INVALID_SOCKET;
        m_error = std::string("bind() failed: ") + strerror(errno);
        return;
    }
    listen(m_socket, connections);
}

std::shared_ptr<Socket> SocketServer::acceptConnections()
{
    std::shared_ptr<Socket> new_socket_ptr = nullptr;
    SOCKET new_socket;
    sockaddr_in addr;
    socklen_t addrsize = sizeof(addr);

    memset(&addr, 0, sizeof(addr));

    new_socket = accept(m_socket, (struct sockaddr *)&addr, &addrsize);
    if (new_socket == INVALID_SOCKET) {
        m_error = std::string("accept() failed: ") + strerror(errno);
    }
    else{
        new_socket_ptr = std::make_shared<Socket>(new_socket, std::string(inet_ntoa(addr.sin_addr)), int(addr.sin_port));
        if(new_socket_ptr){
            new_socket_ptr->m_accepted_socket = true;
            if (!m_uds_path.empty()) new_socket_ptr->m_uds_path = m_uds_path;
        }
        else{
            close(new_socket);
            m_error = std::string("Can't allocate new Socket() object");
        }
    }
    
    return new_socket_ptr;
}

SocketClient::SocketClient(const std::string &uds_path, long readTimeout) : Socket(uds_path, readTimeout)
{
    if (m_socket == INVALID_SOCKET) {
        m_error = "socket != INVALID_SOCKET";
        return;
    }

    m_uds_path = uds_path;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    imif::common::string_utils::copy_string(addr.sun_path, uds_path.c_str(), sizeof(addr.sun_path));

    if (::connect(m_socket, (sockaddr *)&addr, sizeof(addr))) {
        m_error = "connect() to " + uds_path + " failed: " + strerror(errno);
    }
}

SocketClient::SocketClient(const std::string &host, int port, int connect_timeout_msec, long readTimeout)
    : Socket(std::string(), readTimeout)
{
    sockaddr_in addr;

    if (m_socket == INVALID_SOCKET) {
        m_error = "socket != INVALID_SOCKET";
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    memset(&(addr.sin_zero), 0, 8);

    // get host address
    if (inet_pton(AF_INET, host.c_str(), &(addr.sin_addr)) != 1) {
        // check if can resolve name //
        sockaddr addr_;
        if (!getnameinfo(&addr_, sizeof(addr_), (char *)host.c_str(), host.length(), NULL, 0, 0)) {
            m_error = "no such host:" + host;
            return;
        }
        addr.sin_addr = ((struct sockaddr_in *)&addr_)->sin_addr;
    }

    m_peer_ip = host;
    m_peer_port = port;

    if (connect_timeout_msec < 0) {
        if (::connect(m_socket, (sockaddr *)&addr, sizeof(sockaddr))) {
            m_error = "connect() to " + host + " failed: " + strerror(errno);
            close(m_socket);
            m_socket = INVALID_SOCKET;
        }
        return;
    }

    // check connection for none block connect //
    int flags = fcntl(m_socket, F_GETFL, 0);
    if (flags < 0) {
        m_error = "can't read socket flags";
        close(m_socket);
        m_socket = INVALID_SOCKET;
        return;
    }
    flags = flags | O_NONBLOCK;
    if (fcntl(m_socket, F_SETFL, flags) != 0) {
        m_error = "set O_NONBLOCK failed";
        close(m_socket);
        m_socket = INVALID_SOCKET;
        return;
    }

    ::connect(m_socket, (sockaddr *)&addr, sizeof(sockaddr));

    fd_set set;
    FD_ZERO(&set);
    FD_SET(m_socket, &set);
    struct timeval timeout;
    timeout.tv_sec = (connect_timeout_msec / 1000);
    timeout.tv_usec = 1000 * (connect_timeout_msec % 1000);
    int max_s = int(m_socket) + 1;
    int ret = select(max_s, NULL, &set, NULL, &timeout);
    if (ret != 1) {
        m_error = "connection timeout!";
        close(m_socket);
        m_socket = INVALID_SOCKET;
        return;
    }

    flags = (flags & ~O_NONBLOCK);
    fcntl(m_socket, F_SETFL, flags);
}

SocketSelect::SocketSelect()
{
    m_socketTval = NULL;
    m_isBlocking = true;
    m_socketVec.clear();
    FD_ZERO(&m_socketSet);
}

SocketSelect::~SocketSelect() { m_socketVec.clear(); }

void SocketSelect::setTimeout(timeval *tval)
{
    if (tval) {
        if (m_socketTval == NULL) {
            m_socketTval = new timeval;
        }
        m_socketTval->tv_sec = tval->tv_sec;
        m_socketTval->tv_usec = tval->tv_usec;
        m_isBlocking = false;
    } else {
        if (m_socketTval) {
            delete m_socketTval;
            m_socketTval = NULL;
            m_isBlocking = true;
        }
    }
}

void SocketSelect::addSocket(std::shared_ptr<Socket> sd)
{
    if (!sd)
        return;

    // Make sure the socket in not in the select
    for (auto soc : m_socketVec) {
        if (soc->getSocketFd() == sd->getSocketFd()) {
            return;
        }
    }

    m_socketVec.push_back(sd);
}

void SocketSelect::removeSocket(std::shared_ptr<Socket> sd)
{
    unsigned i;
    if (sd) {
        for (i = 0; i < m_socketVec.size(); i++) {
            if (m_socketVec[i]->getSocketFd() == sd->getSocketFd()) {
                break;
            }
        }
        if (i < m_socketVec.size()) {
            m_socketVec.erase(m_socketVec.begin() + i);
        }
    }
}

void SocketSelect::clearReady(std::shared_ptr<Socket> sd)
{
    if (sd) {
        FD_CLR(sd->m_socket, &m_socketSet);
    }
}

int SocketSelect::selectSocket()
{
    int max_s = 0;
    FD_ZERO(&m_socketSet);
    for (unsigned i = 0; i < m_socketVec.size(); i++) {
        FD_SET(m_socketVec[i]->m_socket, &m_socketSet);
        if (max_s < m_socketVec[i]->m_socket)
            max_s = (int)m_socketVec[i]->m_socket;
    }
    // create a copy of m_socketTval for select() //
    timeval timeout;
    timeval *p_timeout;
    if (m_socketTval) {
        timeout = *m_socketTval;
        p_timeout = &timeout;
    } else {
        p_timeout = nullptr;
    }
    return select(max_s + 1, &m_socketSet, (fd_set *)0, (fd_set *)0, p_timeout);
}

std::shared_ptr<Socket> SocketSelect::at(size_t idx) { return ((idx < m_socketVec.size()) ? m_socketVec[idx] : nullptr); }

bool SocketSelect::readReady(std::shared_ptr<Socket> sd)
{
    if ((!sd) && (sd->m_socket != INVALID_SOCKET)) {
        return (FD_ISSET(sd->m_socket, &m_socketSet)) ? true : false;
    } else {
        return false;
    }
}

bool SocketSelect::readReady(size_t idx)
{
    if (idx < m_socketVec.size()) {
        return readReady(m_socketVec[idx]);
    } else {
        return false;
    }
}

SocketPoll::SocketPoll(uint timeout) : m_epoll_fd(-1), m_timeout(timeout)
{
    m_sockets_map.clear();
    if ((m_epoll_fd = epoll_create1(0)) == -1) {
        LOG(ERROR) << "Failed creating epoll: " << strerror(errno);
    }
}

SocketPoll::~SocketPoll()
{
    if (m_epoll_fd > 0) {
        close(m_epoll_fd);
        m_epoll_fd = -1;
    }
}

bool SocketPoll::add_socket(std::shared_ptr<Socket> socket, uint32_t additional_flags)
{
    // Create the epoll on first use
    if (m_epoll_fd < 0) {
        if ((m_epoll_fd = epoll_create1(0)) == -1) {
            LOG(ERROR) << "Failed creating epoll: " << strerror(errno);
            return false;
        }
    }

    if (!socket) {
        LOG(ERROR) << "socket is nullptr!";
        return false;
    }

    // Make sure that the FD is not already part of the poll
    if (m_sockets_map.find(socket->getSocketFd()) != m_sockets_map.end()) {
        LOG(WARNING) << "Requested to add FD (" << socket->getSocketFd() << ") to the poll, but it's already there...";

        return false;
    }

    // Add the socket to the poll
    // Register for incoming data and error events
    epoll_event event;
    event.data.fd = socket->getSocketFd();
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP | additional_flags;
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, event.data.fd, &event) == -1) {
        LOG(ERROR) << "Failed adding FD (" << event.data.fd << ") to the poll: " << strerror(errno);

        return false;
    }

    // Add the FD to the map
    m_sockets_map[event.data.fd] = socket;

    return true;
}

bool SocketPoll::del_socket(std::shared_ptr<Socket> socket)
{
    // Validate epoll file descriptor
    if (m_epoll_fd < 0) {
        LOG(ERROR) << "Poll not initialized!";
        return false;
    }

    if (!socket) {
        LOG(ERROR) << "socket is nullptr!";
        return false;
    }

    // Make sure that the FD was previously added to the poll
    if (m_sockets_map.find(socket->getSocketFd()) == m_sockets_map.end()) {
        LOG(WARNING) << "Requested to delete FD (" << socket->getSocketFd() << ") from the poll, but it wasn't previously added.";

        return false;
    }

    // Delete the socket from the poll
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, socket->getSocketFd(), nullptr) == -1) {
        LOG(ERROR) << "Failed deleting FD (" << socket->getSocketFd() << ") from the poll: " << strerror(errno);

        return false;
    }

    // Add the FD to the map
    m_sockets_map.erase(socket->getSocketFd());

    return true;
}

int SocketPoll::poll(socket_handler_t data_handler, socket_handler_t error_handler, socket_handler_t disconnect_handler)
{
    // Support up to 16 concurrent events
    epoll_event events[16] = {0};

    // Validate epoll file descriptor
    if (m_epoll_fd < 0) {
        LOG(ERROR) << "Poll not initialized!";
        return -1;
    }

    // Poll the sockets
    int sock_num = epoll_wait(m_epoll_fd, events, sizeof(events), m_timeout);

    if (sock_num == -1) {
#ifdef COMMON_DEBUG_FLAG
        if (errno == EINTR) {
            return 0; // retry, probably interrupted by gdb
        }
#endif

        LOG(ERROR) << "Error during epoll_wait: " << strerror(errno);
        return -1;
    } else if (sock_num == 0) {
        // Timeout... Do nothing
        return 0;
    }

    // Trigger event handlers
    for (int i = 0; i < sock_num; i++) {
        int fd = events[i].data.fd;
        auto socket_iter = m_sockets_map.find(fd);

        if (socket_iter == m_sockets_map.end()) {
            LOG(ERROR) << "Event on unknown FD: " << fd;
            continue;
        }

        // Handle errors
        if (events[i].events & EPOLLERR) {

            // Read the error from the socket
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            LOG(ERROR) << "Error on FD (" << fd << "): " << strerror(error);

            if (error_handler) {
                if (!error_handler(socket_iter->second)) {
                    return -1;
                }
            }
            del_socket(socket_iter->second);

            // Handle Disconnected Sockets
        } else if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP)) {
            LOG(DEBUG) << "Socket with FD (" << fd << ") disconnected";
            if (disconnect_handler) {
                if (!disconnect_handler(socket_iter->second)) {
                    return -1;
                }
            }
            del_socket(socket_iter->second);

            // Handle Data
        } else if (events[i].events & EPOLLIN) {
            if (!data_handler(socket_iter->second)) {
                // Stop event processing and return
                LOG(ERROR) << "Failed processing FD (" << fd << ")";
                return -1;
            }
        } else {
            LOG(ERROR) << "FD (" << fd << ") generated unknown event: " << events[i].events;
        }
    }

    return sock_num;
}
