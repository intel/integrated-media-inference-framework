
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

#include "../include/common_broker_thread.h"

// System
#include <cerrno>

#include <easylogging++.h>

#include <google/protobuf/util/json_util.h>

std::string ProtoToJson(const google::protobuf::Message &proto)
{
    std::string json;
    struct google::protobuf::util::JsonPrintOptions jsonOptions;
    jsonOptions.always_print_primitive_fields = true;
    google::protobuf::util::MessageToJsonString(proto, &json, jsonOptions);
    return json;
}

std::ostream &operator<<(std::ostream &os, const std::shared_ptr<google::protobuf::Message> &proto)
{
    os << ProtoToJson(*proto.get());
    return os;
}

std::ostream &operator<<(std::ostream &os, const google::protobuf::Message &proto)
{
    os << ProtoToJson(proto);
    return os;
}

namespace imif {
namespace common {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

// Override easylogging LOG definition adding the thread name
#ifdef LOG
#undef LOG
#endif
static thread_local std::string s_thread_name;
#define LOG(LEVEL) CLOG(LEVEL, ELPP_CURR_FILE_LOGGER_ID) << s_thread_name

// Default select timeout (in milliseconds)
#define DEFAULT_SOCKET_SELECT_TIMEOUT 500
#define DEFAULT_MAX_SOCKET_CONNECTIONS 10

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

broker_thread::broker_thread(const std::string &thread_name, const std::string &broker_uds_path, std::string host,
                             int broker_tcp_port)
    : m_broker_uds_path(broker_uds_path), m_broker_tcp_port(broker_tcp_port), m_broker_tcp_host(host),
      m_socket_poll(DEFAULT_SOCKET_SELECT_TIMEOUT)
{
    this->thread_name = thread_name;
}

broker_thread::~broker_thread() {}

bool broker_thread::init()
{
    // Connect to the message broker
    if (!m_broker_uds_path.empty()) {
        m_broker_socket = std::make_shared<SocketClient>(m_broker_uds_path);
        if (!m_broker_socket) {
            LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds_path;
            return false;
        } 
        const auto error_msg = m_broker_socket->getError();
        if (!error_msg.empty()) {
            LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds_path
                       << " [ERROR: " << error_msg << "]";
            m_broker_socket.reset();
            return false;
        }
        LOG(DEBUG) << "new socket with broker " << m_broker_uds_path;
    }

    // Handle TCP socket
    if (m_broker_tcp_port > 0) {
        m_broker_tcp_socket = std::make_shared<SocketClient>(m_broker_tcp_host, m_broker_tcp_port);
        if (!m_broker_tcp_socket) {
            LOG(ERROR) << "tcp_server_socket == nullptr";
            return false;
        }
        const auto error_msg = m_broker_tcp_socket->getError();
        if (!error_msg.empty()) {
            LOG(ERROR) << "Error with TCO socket: " << error_msg;
            m_broker_tcp_socket.reset();
            return false;
        }
        LOG(DEBUG) << "new SocketClient on host " << m_broker_tcp_host << " TCP port " << m_broker_tcp_port;
    }

    // Add the sockets to the poll
    if (m_broker_tcp_socket && !add_socket(m_broker_tcp_socket, true)) {
        LOG(ERROR) << "Failed adding the TCP server socket into the poll";
        return false;
    }

    if (m_broker_socket && !add_socket(m_broker_socket, true)) {
        LOG(ERROR) << "Failed adding the broker socket into the poll";
        return false;
    }

    // Execute any user post-init logic
    return post_init();
}

bool broker_thread::work()
{
    // Initialize the s_thread_name local thread variable
    if (s_thread_name.empty()) {
        s_thread_name = "[" + thread_name + "]: ";
        LOG(INFO) << "Running...";
    }

    // Invoke any before select logic
    if (!before_select()) {
        LOG(ERROR) << "before_select() failed!";
        return false;
    }

    // Wait for socket evetns
    int poll_ret = m_socket_poll.poll(
        // Data handler
        [&](std::shared_ptr<Socket> socket) {
            // Accept incoming connections
            if ((m_broker_socket && socket->getSocketFd() == m_broker_socket->getSocketFd()) ||
                (m_broker_tcp_socket && socket->getSocketFd() == m_broker_tcp_socket->getSocketFd())) {
                // Read and parse a protobuf message from the socket
                while (socket->getBytesReady()) {
                    messages::sProtoHeader header;
                    int ret = read_proto_message(socket, header, m_rx_buffer, sizeof(m_rx_buffer));
                    if (ret < 0) {
                        LOG(ERROR) << "Failed reading and/or parsing message!";
                        return false;
                    } else if (ret == 0) {
                        return true;
                    }

                    // Handle the incoming message
                    if (!handle_msg(socket, messages::enums::Opcode(header.opcode), (header.length) ? m_rx_buffer : nullptr,
                                    (header.length) ? header.length : 0)) {
                        return false;
                    }
                }
                return true;
            }

            return handle_msg(socket);
        },

        // Error Handler
        [&](std::shared_ptr<Socket> socket) {
            if ((m_broker_socket && socket->getSocketFd() == m_broker_socket->getSocketFd()) ||
                (m_broker_tcp_socket && socket->getSocketFd() == m_broker_tcp_socket->getSocketFd())) {
                LOG(ERROR) << "Error on the broker socket!";
                return false;
            }
            return socket_error(socket);
        },

        // Disconnect Handler
        [&](std::shared_ptr<Socket> socket) {
            LOG(DEBUG) << "Socket disconnected: FD(" << socket->getSocketFd() << ")";

            if ((m_broker_socket && socket->getSocketFd() == m_broker_socket->getSocketFd()) ||
                (m_broker_tcp_socket && socket->getSocketFd() == m_broker_tcp_socket->getSocketFd())) {
                LOG(ERROR) << "Broker socket disconnected!!";
                return false;
            }

            return socket_disconnected(socket);
        });

    // Poll error
    if (poll_ret == -1) {
        LOG(ERROR) << "Poll error!";
        return false;
    }

    // Invoke any after select logic
    if (!after_select(poll_ret == 0)) {
        LOG(ERROR) << "after_select() failed!";
    }

    return true;
}

bool broker_thread::send_msg(messages::enums::Opcode opcode, const google::protobuf::Message &msg)
{
    auto sd = m_broker_tcp_socket ? m_broker_tcp_socket : m_broker_socket;
    return send_msg(sd, opcode, &msg);
}

bool broker_thread::send_msg(messages::enums::Opcode opcode, const google::protobuf::Message *msg)
{
    auto sd = m_broker_tcp_socket ? m_broker_tcp_socket : m_broker_socket;
    return send_msg(sd, opcode, msg);
}

bool broker_thread::send_msg(std::shared_ptr<imif::common::Socket> socket, uint32_t opcode, const google::protobuf::Message &msg)
{
    return send_msg(socket, opcode, &msg);
}

bool broker_thread::send_msg(std::shared_ptr<imif::common::Socket> socket, uint32_t opcode, const google::protobuf::Message *msg)
{
    if (!socket) {
        LOG(ERROR) << "Invalid broker socket!";
        return false;
    }

    if (msg && !msg->IsInitialized()) {
        LOG(ERROR) << "Trying to send uninitialized message!";
        return false;
    }

    // Build the message header
    imif::messages::sProtoHeader header;
    header.magic = messages::enums::Consts::MAGIC;
    header.length = (msg) ? msg->ByteSizeLong() : 0;
    header.opcode = int(opcode);

    size_t bytes_write_pending = socket->getBytesWritePending();
    size_t buffer_size = socket->getBufferLength();
    if (buffer_size < bytes_write_pending + sizeof(header) + header.length) {
        LOG(ERROR) << "Not enough space to send the msg! buffer_size=" << buffer_size
                   << " size=" << bytes_write_pending + sizeof(header) + header.length;
        return false;
    }

    // Send the message header
    auto status = socket->writeBytes((const uint8_t *)&header, sizeof(header));
    if (status != sizeof(header)) {
        LOG(ERROR) << "Failed sending message header! Error " << strerror(errno);
        return false;
    }

    // Send the message payload (if available)
    if ((msg) && !msg->SerializeToFileDescriptor(socket->getSocketFd())) {
        LOG(ERROR) << "Failed sending message payload!";
        return false;
    }

    return true;
}

size_t broker_thread::get_free_send_buffer_size(std::shared_ptr<imif::common::Socket> socket)
{
    if (!socket) {
        return 0;
    }

    size_t bytes_write_pending = socket->getBytesWritePending();
    size_t buffer_size = socket->getBufferLength();
    if (buffer_size > bytes_write_pending) {
        return (buffer_size - bytes_write_pending);
    }

    return 0;
}

size_t broker_thread::get_free_send_buffer_size() { return get_free_send_buffer_size(m_broker_socket); }

bool broker_thread::subscribe(messages::enums::Opcode opcode) { return subscribe(std::list<messages::enums::Opcode>({opcode})); }

bool broker_thread::subscribe(std::shared_ptr<imif::common::Socket> sd, messages::enums::Opcode opcode)
{
    return subscribe(sd, std::list<messages::enums::Opcode>({opcode}));
}

bool broker_thread::subscribe(std::shared_ptr<imif::common::Socket> sd, const std::list<messages::enums::Opcode> &opcodes_list)
{
    // Build the subscription message to the broker
    imif::messages::broker_subscribe msg;
    for (auto &opcode : opcodes_list) {
        msg.add_opcode(opcode);
    }

    // Send the message
    return send_msg(sd, imif::messages::enums::Opcode::BROKER_SUBSCRIBE, msg);
}

bool broker_thread::subscribe(const std::list<messages::enums::Opcode> &opcodes_list)
{
    return subscribe(m_broker_socket, opcodes_list);
}

bool broker_thread::unsubscribe(messages::enums::Opcode opcode)
{
    return unsubscribe(std::list<messages::enums::Opcode>({opcode}));
}

bool broker_thread::unsubscribe(const std::list<messages::enums::Opcode> &opcodes_list)
{
    // Build the unsubscription message to the broker
    imif::messages::broker_unsubscribe msg;
    for (auto &opcode : opcodes_list) {
        msg.add_opcode(opcode);
    }

    // Send the message
    return send_msg(imif::messages::enums::Opcode::BROKER_UNSUBSCRIBE, msg);
}

bool broker_thread::socket_server_accept(std::shared_ptr<SocketServer> &server_socket)
{
    // Accept the connection
    auto new_socket = server_socket->acceptConnections();
    const auto error_msg = server_socket->getError();
    if (!new_socket || (!error_msg.empty())) {
        LOG(ERROR) << "ServerSocket Error: " << error_msg;
        return false;
    }

    // Log the connection
    if (!server_socket->getUdsPath().empty()) {
        LOG(DEBUG) << "new connection on " << server_socket->getUdsPath() << " sd = " << uintptr_t(new_socket.get());
    } else {
        LOG(DEBUG) << "new connection from ip = " << new_socket->getPeerIP() << " port = " << new_socket->getPeerPort()
                   << " sd = " << uint64_t(new_socket.get());
    }

    // Add the accepted socket to the select
    socket_connected(new_socket);
    return true;
}

bool broker_thread::socket_connected(std::shared_ptr<Socket> sd)
{
    // Add the newly accepted socket into the poll
    if (!add_socket(sd)) {
        LOG(ERROR) << "Failed adding new socket into the poll!";
        return false;
    }

    return true;
}

bool broker_thread::socket_disconnected(std::shared_ptr<Socket> sd)
{
    LOG(DEBUG) << "Socket disconnected: FD(" << sd->getSocketFd() << ")";

    return true;
}

int broker_thread::read_proto_message(std::shared_ptr<imif::common::Socket> socket, messages::sProtoHeader &header, uint8_t *buff,
                                      int buff_len)
{
    // Check if the socket contains enough bytes for the header
    if (socket->getBytesReady() < sizeof(messages::sProtoHeader)) {
        // Received partial header - do nothing...
        return 0;
    }

    // Peek into the header to check if the entire message received
    auto msg_len = socket->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), true);
    if (msg_len != sizeof(header)) {
        LOG(ERROR) << "Error peeking into the message header: " << msg_len;
        return -1;
    }

    // Validate the header
    if (header.magic != messages::enums::Consts::MAGIC || header.opcode == (int)messages::enums::INVALID) {
        LOG(ERROR) << "Invalid message header: magic = 0x" << std::hex << header.magic << std::dec << ", length = " << header.length
                   << ", opcode = " << header.opcode;

        // Discard the (invalid) header bytes
        socket->readBytes(buff, sizeof(header), sizeof(header));
        return -1;
    }

    // Read the message header
    msg_len = socket->readBytes((uint8_t *)&header, sizeof(header), sizeof(header), false, true);
    if (msg_len != sizeof(header)) {
        LOG(ERROR) << "Error reading the message header: " << msg_len;
        return -1;
    }

    // Read the message payload (if exists)
    if (header.length) {
        msg_len = socket->readBytes(buff, buff_len, header.length, false, true);
        if (msg_len != header.length) {
            LOG(ERROR) << "Error reading the message: " << msg_len;
            return -1;
        }
    }

    return 1;
}

} // namespace common
} // namespace imif
