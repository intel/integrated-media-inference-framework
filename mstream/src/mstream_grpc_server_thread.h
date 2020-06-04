
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

#ifndef _GrpcServerThread_H
#define _GrpcServerThread_H

#include <chrono>
#include <functional>
#include <grpcpp/grpcpp.h>
#include <messages/grpc/msl_services.grpc.pb.h>
#include <messages/proto/inference.pb.h>
#include <messages/proto/msl.pb.h>
#include <messages/proto/types.pb.h>
#include <opencv2/core/mat.hpp>

#include "common_broker_thread.h"
#include "common_mem_manager.h"
#include "common_os_utils.h"
#include "mstream_publisher.h"
#include "mstream_result_thread.h"

namespace imif {
namespace mstream {

class listen_call_data;
class GrpcServerThread : public common::thread_base {
public:
    struct FlowContext {
        std::shared_ptr<imif::common::shmem_pool> pool;
        uint64_t highest_frame_number;
        std::unordered_set<uint32_t> next_stages;
    };

public:
    GrpcServerThread(const std::string broker_uds_path);
    ~GrpcServerThread();
    void clear();

    bool set_listening_port(const std::string port_str);
    bool set_listening_port(const int32_t port);
    bool add_flow(uint32_t flow_id, const messages::types::Stage &stage);
    std::unordered_set<uint32_t> &sources() { return m_sources; }
    std::unordered_map<uint32_t, FlowContext> &flows() { return m_flows; }
    uint64_t dropped_bytes() { return m_dropped_bytes; }
    uint64_t sent_bytes() { return m_sent_bytes; }
    uint64_t time_spent_decoding_usec() { return m_time_spent_decoding_usec; }
    uint64_t sent_frames() { return m_sent_frames; }
    std::shared_ptr<imif::common::SocketClient> broker_socket() { return m_broker_socket; }

    void add_dropped_bytes(uint64_t val) { m_dropped_bytes += val; }
    void add_sent_bytes(uint64_t val) { m_sent_bytes += val; }
    void add_time_spent_decoding_usec(uint64_t val) { m_time_spent_decoding_usec += val; }
    void add_sent_frames(uint64_t val) { m_sent_frames += val; }

    void reset_stats();
    bool enable();
    bool enabled() { return m_enabled; }
    bool handle_subscribe(imif::messages::msl::SubscriptionRequest &subcription_request, subscriber *sub);
    bool handle_unsubscribe(imif::messages::msl::SubscriptionRequest &subcription_request, subscriber *sub);
    uint32_t next_client_id() { return m_next_client_id++; }
    listen_call_data *listener_by_id(uint32_t client_id);
    bool register_listener(uint32_t listener_id, listen_call_data *call_data);
    void remove_listener(uint32_t listener_id);
    imif::messages::msl::ChunkResponseOptions send_chunk(const std::string &content, uint32_t flow_id);

protected:
    virtual bool init() override;
    virtual void on_thread_stop() override;
    bool start_grpc_server();
    void shutdown_grpc_server();
    virtual bool work() override;
    void before_stop() override;

    static void shutdown_grpc_server(std::shared_ptr<grpc::ServerCompletionQueue> &cq, std::unique_ptr<grpc::Server> &server);

    const std::string m_broker_uds_path;
    const static int32_t default_port = 50055;
    std::shared_ptr<imif::common::SocketClient> m_broker_socket = nullptr;

private:
    bool m_enabled = false;
    int32_t m_port = -1;
    std::unique_ptr<grpc::ServerCompletionQueue> m_cq;
    services::msl::StreamingLibrary::AsyncService *m_service = nullptr;
    std::unique_ptr<grpc::Server> m_server;
    uint64_t m_dropped_bytes = 0;
    uint64_t m_sent_bytes = 0;
    uint64_t m_time_spent_decoding_usec = 0;
    uint64_t m_sent_frames = 0;

    std::unordered_set<uint32_t> m_sources;              // key = source_id
    std::unordered_map<uint32_t, FlowContext> m_flows;   // key = flow_id
    std::map<size_t, listen_call_data *> m_listener_map; // key = client_id
    uint32_t m_next_client_id = 1984;
    std::shared_ptr<result_thread> m_result_thread;
    bool m_server_started = false;
};

// Base class used to cast the void* tags we get from
// the completion queue and call Process() on them.
class base_call_data {
public:
    base_call_data();
    virtual ~base_call_data();
    virtual void process(GrpcServerThread *this_thread) = 0;
    virtual void finish(bool ok);

    void deallocate();

    static base_call_data *validate_cast(void *ptr);
    static void init(imif::services::msl::StreamingLibrary::AsyncService *service, grpc::ServerCompletionQueue *cq);

protected:
    static services::msl::StreamingLibrary::AsyncService *s_service;

    static grpc::ServerCompletionQueue *s_cq;

    grpc::ServerContext m_ctx;

    enum CallStatus { INIT, READY, PROCESS, FINISH };

    CallStatus m_status;

    static std::set<void *> s_all_calls;
};

class ping_call_data : public base_call_data {
public:
    ping_call_data();
    void process(GrpcServerThread *this_thread);

protected:
    void process_frame();

private:
    grpc::ServerAsyncResponseWriter<imif::messages::msl::PingResponse> m_responder;
    imif::messages::msl::PingRequest m_command;
    imif::messages::msl::PingResponse m_output;
};

class connect_call_data : public base_call_data {
public:
    connect_call_data();
    void process(GrpcServerThread *this_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::msl::ConnectResponse> m_responder;
    imif::messages::msl::ConnectRequest m_command;
    imif::messages::msl::ConnectResponse m_output;
};

struct infer_work_item {
    infer_work_item(std::shared_ptr<cv::Mat> _rgbMat, std::shared_ptr<imif::common::shmem_buff> _rgb_shmem_buff,
                    const imif::messages::types::FrameData &_frame_data)
        : rgbMat(_rgbMat), rgb_shmem_buff(_rgb_shmem_buff), frame_data(_frame_data)
    {
    }
    std::shared_ptr<cv::Mat> rgbMat;
    std::shared_ptr<imif::common::shmem_buff> rgb_shmem_buff;
    const imif::messages::types::FrameData &frame_data;
};

class infer_call_data : public base_call_data {
public:
    infer_call_data();
    void process(GrpcServerThread *this_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::msl::InferResponse> m_responder;
    imif::messages::msl::InferRequest m_request;
    imif::messages::msl::InferResponse m_output;

    std::vector<infer_work_item> m_work_items;

    void prepare_frames(GrpcServerThread *);
    void process_frames(GrpcServerThread *);
    static bool get_image_dimensions(const std::string &img_data, int &height, int &width);
};

class subscribe_call_data : public base_call_data {
public:
    subscribe_call_data(GrpcServerThread *this_thread);
    void process(GrpcServerThread *grpc_thread);

private:
    grpc::ServerAsyncResponseWriter<imif::messages::msl::SubscriptionResponse> m_responder;
    imif::messages::msl::SubscriptionRequest m_command;
    imif::messages::msl::SubscriptionResponse m_output;
    GrpcServerThread *m_thread;
};

class listen_call_data : public base_call_data, public subscriber {
public:
    listen_call_data(GrpcServerThread *server);

    void process(GrpcServerThread *grpc_thread);
    void publish_event(uint32_t flow_id, const messages::types::ResultReady &message) override;
    void stop_listening();

private:
    void publish_event_safe(uint32_t flow_id, const messages::types::ResultReady &message);
    grpc::ServerAsyncWriter<imif::messages::msl::Event> m_responder;
    imif::messages::msl::ClientID m_command;
    std::queue<std::pair<uint32_t, messages::types::ResultReady>> m_outstanding_events;
    std::recursive_mutex m_publishing_mutex;
    uint32_t m_id;
    GrpcServerThread *m_thread;
};

class receive_stream_call_data : public base_call_data {
public:
    receive_stream_call_data();

    void process(GrpcServerThread *this_thread);
    void stop();
    void finish(bool ok);

private:
    grpc::ServerAsyncReaderWriter<imif::messages::msl::ChunkResponse, imif::messages::msl::Chunk> m_reader_writer;
    imif::messages::msl::Chunk m_chunk;
    imif::messages::msl::ChunkResponse m_response;
};

} // namespace mstream
} // namespace imif

#endif
