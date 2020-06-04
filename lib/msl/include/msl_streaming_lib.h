
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

#ifndef _MSL_H
#define _MSL_H

#include "common_logging.h"
#include <grpcpp/grpcpp.h>
#include <messages/grpc/msl_services.grpc.pb.h>
#include <messages/proto/msl.pb.h>
#include <messages/proto/types.pb.h>

#include <arpa/inet.h>
#include <map>
#include <memory>
#include <string>
#include <thread>

namespace imif {
namespace mstream {

using CallbackFunc = std::function<void(const messages::msl::Event &)>;
class streaming_client {
public:
    streaming_client();
    ~streaming_client();

    /**
     * @brief Connect to the msl server
     * 
     * @param host_or_ip_str hostname of ip address of the server
     * @param port_str the port the server is listening on
     * @return true on success
     * @return false on failure
     */
    bool connect(std::string &host_or_ip_str, std::string port_str = "");

    /**
     * @brief Disconnect from the server
     * 
     */
    void disconnect();

    /**
     * @brief Check the connection to the msl server
     * 
     * @return true if there's a connection
     * @return false there
     */
    bool is_connected();

    /**
     * @brief Get the client id, alloted on connection
     * 
     * @return uint32_t a unique ID of this client
     */
    uint32_t get_client_id();

    /**
     * @brief Run the inference for a particular flow
     * 
     * @param flow_id The flow to run the inference on
     * @param frame_format Enum specifying format of the frames
     * @param frames_data Width/height and payload
     * @param response The response of the inference, reporting if the inference was successful
     * @return true on success
     * @return false on failure
     */
    bool infer(const uint32_t flow_id, const imif::messages::enums::FrameFormat frame_format,
               const imif::messages::types::FramesData &frames_data, imif::messages::msl::InferResponse &response);

    /**
     * @brief Subscribe to inference results of a particular flow. 
     *        For each result the callback registered by register_listener_callback() will be run.
     * 
     * @param flow_id The ID of the flow
     * @param stage_id The ID of the stage we want to get results from
     * @param subscribe A boolean specifying if we want to subscribe or unsubscribe
     * @return true on success
     * @return false on failure 
     */
    bool subscribe(uint32_t flow_id, uint32_t stage_id, bool subscribe);

    /**
     * @brief Register a callback to be run on every message we're subscribed to
     * 
     * @param callback the callback.
     */
    void register_listener_callback(CallbackFunc callback);

    /**
     * @brief Start streaming a video file cyclicly
     * 
     * @param filename The file to stream
     * @param flow_id A unique id
     * @param max_rate Maximum rate for streaming to be in, 0 for unlimited
     */
    bool start_stream_file(const std::string &filename, uint32_t flow_id, float max_mbps = 0);
    /**
     * @brief Stop streaming file
     * 
     * @param flow_id an identifyer of the stream
     */
    bool stop_stream_file(uint32_t flow_id);

    static const size_t max_message_size = 128 * 1024 * 1024; // in bytes
    static const int32_t default_port = 50055;

private:
    bool listen();
    bool check_error(grpc::Status &status);
    bool connect_to_server();
    void event_dispatch();
    void stop_listen();
    bool stream_file(const std::string &filename, uint32_t flow_id, float max_mbps);
    void remove_thread(uint32_t flow_id);
    class remove_thread_raii {
    public:
        remove_thread_raii(uint32_t flow_id, streaming_client *sc) : m_flow_id(flow_id), m_streaming_client(sc) {}
        ~remove_thread_raii()
        {
            if (m_streaming_client) {
                m_streaming_client->remove_thread(m_flow_id);
            }
        }

    private:
        uint32_t m_flow_id;
        streaming_client *m_streaming_client;
    };

    uint32_t m_client_id = 0;

    std::shared_ptr<grpc::Channel> m_channel = nullptr;
    std::unique_ptr<services::msl::StreamingLibrary::Stub> m_stub = nullptr;

    std::shared_ptr<grpc::CompletionQueue> m_listener_cq = nullptr;
    std::unique_ptr<::grpc::ClientAsyncReader<messages::msl::Event>> m_event_reader = nullptr;
    std::shared_ptr<grpc::ClientContext> m_listener_context = nullptr;
    std::thread m_event_dispatch_thread = std::thread();
    std::atomic_bool m_listener_thread_running{};
    CallbackFunc m_listener_callback = nullptr;
    const uint64_t MAX_CHUNK_SIZE = 64 * 1024;
    std::map<uint32_t, std::thread> m_streaming_threads;
    std::mutex m_streaming_thread_mutex;
    std::map<uint32_t, bool> m_thread_should_stop;
};
} // namespace mstream
} // namespace imif
#endif
