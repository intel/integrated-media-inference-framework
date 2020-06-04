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

#include "broker_server.h"

// Common
#include <messages/header.h>

// Messages
#include <messages/proto/broker_control.pb.h>

// System
#include <cerrno>
#include <sys/uio.h>

#include <easylogging++.h>

namespace imif {
namespace broker {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

// Override easylogging LOG definition adding the thread name
#ifdef LOG
#undef LOG
#endif
#define LOG(LEVEL) CLOG(LEVEL, ELPP_CURR_FILE_LOGGER_ID) << std::string("[Broker]: ")

// Default poll timeout (in milliseconds)
#define DEFAULT_SOCKET_POLL_TIMEOUT 500

// Number of concurrent connections on the server socket
#define MAX_SERVER_CONNECTIONS 10

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

static bool is_opcode_restricted(messages::enums::Opcode &opcode)
{
    if (opcode == messages::enums::Opcode::OPCODE_INVALID || opcode == messages::enums::Opcode::BROKER_SUBSCRIBE ||
        opcode == messages::enums::Opcode::BROKER_UNSUBSCRIBE) {
        return true;
    }

    return false;
}

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Broker Implementation ////////////////////////////
//////////////////////////////////////////////////////////////////////////////

broker_server_thread::broker_server_thread(std::string broker_uds_path) : m_broker_uds_path(broker_uds_path)
{
    this->thread_name = "Broker";
    m_fd_to_opcode.clear();
    m_opcode_to_fd.clear();
}

broker_server_thread::~broker_server_thread()
{
    // Stop the thread
    stop();
}

bool broker_server_thread::init()
{
    // Connect to the message broker
    if (!(m_broker_socket = std::make_shared<common::SocketServer>(m_broker_uds_path, MAX_SERVER_CONNECTIONS))) {
        LOG(FATAL) << "Failed allocating memory!";
        return false;
    }

    // Check for connection errors
    auto error_msg = m_broker_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds_path
                   << " [ERROR: " << error_msg << "]";

        m_broker_socket.reset();
        return false;
    }

    // Add the socket to the poll
    if (!m_socket_poll.add_socket(m_broker_socket)) {
        LOG(ERROR) << "Failed adding the broker socket into the poll";
        return false;
    }

    if (!(m_broker_socket_tcp = std::make_shared<common::SocketServer>(messages::enums::TCP_BROKER_PORT, MAX_SERVER_CONNECTIONS))) {
        LOG(FATAL) << "Failed allocating memory!";
        return false;
    }

    // Check for connection errors
    error_msg = m_broker_socket_tcp->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using TCP: " << messages::enums::TCP_BROKER_PORT
                   << " [ERROR: " << error_msg << "]";

        m_broker_socket_tcp.reset();
        return false;
    }

    // Add the socket to the poll
    if (!m_socket_poll.add_socket(m_broker_socket_tcp)) {
        LOG(ERROR) << "Failed adding the broker socket into the poll";
        return false;
    }

    return true;
}

bool broker_server_thread::work()
{
    // Poll the sockets
    auto poll_ret = m_socket_poll.poll(

        // Data handler
        [&](std::shared_ptr<common::Socket> socket) {
            // Accept incoming connections
            if (socket->getSocketFd() == m_broker_socket->getSocketFd()) {
                if (!socket_connected(m_broker_socket)) {
                    // NOTE: Do NOT stop the broker on connection errors...
                }

                return true;
            } else if (socket->getSocketFd() == m_broker_socket_tcp->getSocketFd()) {
                if (!socket_connected(m_broker_socket_tcp)) {
                    // NOTE: Do NOT stop the broker on connection errors...
                }

                return true;

                // Incoming data from a broker client
            } else {

                if (!handle_msg(socket)) {
                    // NOTE: Do NOT stop the broker on parsing errors...
                }

                return true;
            }
        },

        // Error Handler
        [&](std::shared_ptr<common::Socket> socket) {
            if (socket->getSocketFd() == m_broker_socket->getSocketFd() ||
                socket->getSocketFd() == m_broker_socket_tcp->getSocketFd()) {
                LOG(ERROR) << "Error on the broker socket!";
                return false;
            } else {
                if (!socket_disconnected(socket)) {
                    // NOTE: Do NOT stop the broker on errors...
                }
            }

            // Default error handling
            return true;
        },

        // Disconnect Handler
        [&](std::shared_ptr<common::Socket> socket) {
            if (socket->getSocketFd() == m_broker_socket->getSocketFd() ||
                socket->getSocketFd() == m_broker_socket_tcp->getSocketFd()) {
                LOG(ERROR) << "Broker socket disconnected!";
                return false;
            } else {
                if (!socket_disconnected(socket)) {
                    // NOTE: Do NOT stop the broker on errors...
                }
            }

            // Default error handling
            return true;
        });

    // Poll error
    if (poll_ret == -1) {
        LOG(ERROR) << "Poll error!";
        return false;
    }

    return true;
}

bool broker_server_thread::handle_msg(std::shared_ptr<common::Socket> sd)
{
    // Check if the socket contains enough bytes for the header
    if (sd->getBytesReady() < sizeof(messages::sProtoHeader)) {
        // Received partial header - do nothing...
        return true;
    }

    // Peek into the header to check if the entire message received
    messages::sProtoHeader header;
    auto msg_len = sd->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), true);
    if (msg_len != sizeof(header)) {
        LOG(ERROR) << "Error peeking into the message header: " << msg_len;
        return false;
    }

    // Validate the header
    if (header.magic != imif::messages::enums::Consts::MAGIC || header.opcode == (int)messages::enums::INVALID) {
        LOG(ERROR) << "Invalid message header: magic = 0x" << std::hex << header.magic << std::dec << ", length = " << header.length
                   << ", opcode = " << header.opcode << ", fd = " << sd->getSocketFd();

        // Discard the (invalid) header bytes
        sd->readBytes(m_rx_buffer, sizeof(header), sizeof(header));

        return false;
    }

    if (header.length > (RX_BUFFER_SIZE - sizeof(header))) {
        LOG(ERROR) << "header leangh is too large! " << header.length;
        return false;
    }

    // Read the message header
    switch (header.opcode) {
    case messages::enums::Opcode::BROKER_SUBSCRIBE:
    case messages::enums::Opcode::BROKER_UNSUBSCRIBE: {

        msg_len = sd->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), false, true);
        if (msg_len != sizeof(header)) {
            LOG(ERROR) << "Error reading the message header: " << msg_len;
            return false;
        }

        // Read the message payload
        if (header.length) {
            msg_len = sd->readBytes(m_rx_buffer, sizeof(m_rx_buffer), header.length, false, true);
            if (msg_len != header.length) {
                LOG(ERROR) << "Error reading the message: " << msg_len;
                return false;
            }
        }
    } break;
    default:
        break;
    }

    // Handle Subscribe/Unsubsribe messages
    switch (header.opcode) {

    case messages::enums::Opcode::BROKER_SUBSCRIBE: {

        if (!header.length) {
            LOG(ERROR) << "Invalid broker_subscribe message length!";
            return false;
        }

        // Parse the broker_subscribe message
        messages::broker_subscribe msg;
        if (!msg.ParseFromArray(m_rx_buffer, header.length)) {
            LOG(ERROR) << "Failed parsing broker_subscribe message!";
            return false;
        }

        std::string opcodes_str;

        // Subscribe the FD to the requested opcodes
        for (int i = 0; i < msg.opcode_size(); i++) {
            auto opcode = msg.opcode(i);

            // Skip restricted opcodes
            if (is_opcode_restricted(opcode)) {
                LOG(WARNING) << "FD (" << sd->getSocketFd() << ") attempt subscribing to forbidden opcode " << opcode;

                continue;
            }

            // Add to the list of requested opcodes
            opcodes_str += std::to_string(opcode) + " ";

            // Add the opcode to the list of this FD subscriptions
            m_fd_to_opcode[sd->getSocketFd()].insert(opcode);

            // Add the FD to the list of this Opcode subscriptions
            m_opcode_to_fd[opcode].insert(sd->getSocketFd());
        }

        LOG(INFO) << "FD (" << sd->getSocketFd() << ") subscribed to the following opcodes: " << opcodes_str;

        LOG(DEBUG) << "FD (" << sd->getSocketFd() << ") subscriptions: " << m_fd_to_opcode[sd->getSocketFd()];

    } break;

    case messages::enums::Opcode::BROKER_UNSUBSCRIBE: {

        if (!header.length) {
            LOG(ERROR) << "Invalid broker_unsubscribe message length!";
            return false;
        }

        // Parse the broker_unsubscribe message
        messages::broker_unsubscribe msg;
        if (!msg.ParseFromArray(m_rx_buffer, header.length)) {
            LOG(ERROR) << "Failed parsing broker_unsubscribe message!";
            return false;
        }

        std::string opcodes_str;

        // Unsubscribe the FD from the requested opcodes
        for (int i = 0; i < msg.opcode_size(); i++) {
            auto opcode = msg.opcode(i);

            // Skip restricted opcodes
            if (is_opcode_restricted(opcode)) {
                LOG(WARNING) << "FD (" << sd->getSocketFd() << ") attempt subscribing to forbidden opcode " << opcode;

                continue;
            }

            // Add to the list of requested opcodes
            opcodes_str += std::to_string(opcode) + " ";

            // Delete the opcode from the list of this FD subscriptions
            m_fd_to_opcode[sd->getSocketFd()].erase(opcode);

            // Add the FD from the list of this Opcode subscriptions
            m_opcode_to_fd[opcode].erase(sd->getSocketFd());
        }

        LOG(INFO) << "FD (" << sd->getSocketFd() << ") unsubscribed from the following opcodes: " << opcodes_str;

        LOG(DEBUG) << "FD (" << sd->getSocketFd() << ") remaining subscriptions: " << m_fd_to_opcode[sd->getSocketFd()];

    } break;

    // Forward to subscribers
    default: {
        std::unordered_set<int> opcode_set = {};
        auto it = m_opcode_to_fd.find(header.opcode);
        if (it != m_opcode_to_fd.end()) {
            opcode_set.insert(it->second.begin(), it->second.end());
        }

        if (opcode_set.empty()) {
            LOG(DEBUG) << "No subscribers for opcode: " << header.opcode;
            // Clear the buffer
            sd->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), false, true);
            sd->readBytes(m_rx_buffer, sizeof(m_rx_buffer), header.length, false, true);
            return true;
        }

        // Iterate over subscribed FDs
        for (auto &fd : opcode_set) {
            // Skip the FD that originated the message
            if (fd == sd->getSocketFd()) {
                continue;
            }

            size_t bytes_write_pending = common::Socket::sGetBytesWritePending(fd);
            size_t buffer_size = common::Socket::sGetBufferLength(fd);

            if (buffer_size < (bytes_write_pending + sizeof(header) + header.length)) {
                LOG(WARNING) << "Not enough space to send the msg " << std::hex << header.opcode << std::dec << " fd=" << fd
                             << "! buffer_size=" << buffer_size << " size=" << bytes_write_pending + sizeof(header) + header.length;
                usleep(100);
                return true;
            }
        }
        sd->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), false, true);
        if (header.length) {
            sd->readBytes(m_rx_buffer, sizeof(m_rx_buffer), header.length, false, true);
        }

        for (auto &fd : opcode_set) {

            // Skip the FD that originated the message
            if (fd == sd->getSocketFd()) {
                continue;
            }

            LOG(DEBUG) << "Forwarding message with opcode (" << std::hex << header.opcode << std::dec << ") to FD (" << fd << ")";

            struct iovec iov[2];

            // Send IOVEC of header + message
            iov[0].iov_base = &header;
            iov[0].iov_len = sizeof(header);
            iov[1].iov_base = m_rx_buffer;
            iov[1].iov_len = header.length;

            // Forward
            if (writev(fd, iov, (header.length) ? 2 : 1) < 0) {
                LOG(ERROR) << "Failed forwarding message with opcode (" << header.opcode << ") to FD (" << fd << ")"
                           << " - " << strerror(errno);
                continue;
            }
        }
    }
    }

    return true;
}

bool broker_server_thread::socket_connected(std::shared_ptr<common::SocketServer> sd)
{
    const size_t tx_buffer_length = 256 * 1024;
    // Accept the connection
    auto new_socket = sd->acceptConnections();

    // Check for errors
    const auto error_msg = sd->getError();
    if ((!new_socket) || (!error_msg.empty())) {
        LOG(ERROR) << "Socket error: " << error_msg;
        return false;
    }

    if (!sd->getUdsPath().empty()) {
        LOG(DEBUG) << "new connection on " << sd->getUdsPath() << " sd = " << uintptr_t(new_socket.get());
    } else {
        LOG(DEBUG) << "new connection from ip = " << new_socket->getPeerIP() << " port = " << new_socket->getPeerPort()
                   << " sd = " << uint64_t(new_socket.get());
    }

    new_socket->setBufferLength(tx_buffer_length, true);

    // Add the newly accepted socket into the poll
    if (!m_socket_poll.add_socket(new_socket)) {
        LOG(ERROR) << "Failed adding new socket into the poll!";
        return false;
    }

    return true;
}

bool broker_server_thread::socket_disconnected(std::shared_ptr<common::Socket> sd)
{
    LOG(DEBUG) << "Socket disconnected: FD(" << sd->getSocketFd() << ")";

    if (sd->getSocketFd() == m_broker_socket->getSocketFd() || sd->getSocketFd() == m_broker_socket_tcp->getSocketFd()) {
        LOG(ERROR) << "Server socket disconnected!";
        return false;
    }

    // Delete the FD from the list of opcode subscriptions
    for (auto &opcode : m_fd_to_opcode[sd->getSocketFd()]) {
        m_opcode_to_fd[opcode].erase(sd->getSocketFd());
    }

    // Delete the opcode from the list of this FD subscriptions
    m_fd_to_opcode.erase(sd->getSocketFd());

    return true;
}

} // namespace broker
} // namespace imif
