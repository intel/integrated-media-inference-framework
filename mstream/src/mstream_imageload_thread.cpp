
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

#include "mstream_imageload_thread.h"
#include "common_os_utils.h"
#include "common_string_utils.h"
#include <functional>
#include <iostream>
#include <string>

#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mstream.pb.h>
#include <messages/proto/types.pb.h>

#define SHMEM_BUFF_SIZE 128 * 1024

using namespace imif;
using namespace common;
using namespace mstream;

static long GetTimeInMillis()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec) * 1000 + now.tv_usec / 1000;
}

static std::string getFileExt(const std::string &s)
{
    size_t i = s.rfind('.', s.length());
    if (i != std::string::npos) {
        return (s.substr(i + 1, s.length() - i));
    }
    return ("");
}

uint64_t getFileSize(std::ifstream &ifs) // sideeffect reset stream to start....
{
    ifs.seekg(0, std::ios::beg);
    auto fsize = ifs.tellg();
    ifs.seekg(0, std::ios::end);
    fsize = ifs.tellg() - fsize;
    ifs.seekg(0, std::ios::beg);
    return fsize;
}

ImageLoadThread::ImageLoadThread(const messages::types::Source &source, const std::string broker_uds)
    : thread_base(), m_source(source), m_broker_uds(broker_uds)
{
}

ImageLoadThread::~ImageLoadThread() { LOG(TRACE) << "~ImageLoadThread()"; }

void ImageLoadThread::on_thread_stop()
{
    LOG(TRACE) << "on_thread_stop()";
    m_pool = nullptr; //<-- frees the shared memory pool
    m_broker_socket.reset();
    if (m_load_to_ram) {
        if (m_buffered_file) {
            free(m_buffered_file);
        }
    } else {
        m_input_stream.close();
    }

    should_stop = true;
}

bool ImageLoadThread::init()
{
    LOG(INFO) << "ImageLoadThread::init()";
    m_broker_socket = std::make_shared<common::SocketClient>(m_broker_uds);
    if (!m_broker_socket) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds;
        return false;
    }
    const auto error_msg = m_broker_socket->getError();
    if (!error_msg.empty()) {
        LOG(ERROR) << "Failed connecting to the broker using UDS: " << m_broker_uds << " [ERROR: " << error_msg << "]";
        m_broker_socket.reset();
        return false;
    }

    return add_source(m_source);
}

bool ImageLoadThread::work()
{
    const size_t MSG_MIN_BUFF_SIZE = 1024;
    bool started_work = true;

    if (!m_enabled) {
        return true;
    }

    if (!m_pool) {
        return true;
    }

    GetTimeInMillis();

    uint64_t sleep_us = 0;
    if (m_stream_format == "h264") {
        sleep_us = m_bps_sleep_us;
    } else {
        sleep_us = m_frame_rate_us;
    }

    // Fill the whole shmem
    while (m_pool->get_consecutive_free() >= (m_image_size * m_batch_size) && !should_stop) {

        if (sleep_us) { //moderate the rate in which we inject frames to ILB
            auto time_since_last_frame =
                std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - m_prev_frame_timestamp)
                    .count();
            int sleep_period = (int)sleep_us - (int)time_since_last_frame;
            if (started_work) {
                sleep_period -= 1000;
                started_work = false;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(std::max(0, sleep_period)));
        }

        auto free_msg_buf_size = broker_thread::get_free_send_buffer_size(m_broker_socket);
        if (free_msg_buf_size < MSG_MIN_BUFF_SIZE) {
            LOG(WARNING) << "Dropping frame! - free_msg_buf_size = " << free_msg_buf_size;
            return true;
        }

        //allocate chunk from pool
        auto shmem_buff = m_pool->alloc_buff(m_image_size * m_batch_size);
        if (!shmem_buff) {
            LOG(ERROR) << "Failed allocating buff";
            return false;
        }

        uint64_t read_count = 0;
        if (m_load_to_ram) {
            //read batch_size frames from ram
            uint64_t write_offset = 0;
            uint64_t bytes_to_write = m_image_size * m_batch_size;
            while (m_read_offset + bytes_to_write > m_ram_size) {
                uint64_t bytes_to_end = m_ram_size - m_read_offset;
                std::copy_n(m_buffered_file + m_read_offset, bytes_to_end, shmem_buff->ptr() + write_offset);
                write_offset += bytes_to_end;
                m_read_offset = 0;
                bytes_to_write -= bytes_to_end;
            }
            std::copy_n(m_buffered_file + m_read_offset, bytes_to_write, shmem_buff->ptr() + write_offset);
            m_read_offset += bytes_to_write;
            read_count += write_offset + bytes_to_write; // report total read bytes for statistics
        } else {
            //read batch_size frames from file
            do {
                m_input_stream.read((char *)shmem_buff->ptr() + read_count, m_image_size * m_batch_size - read_count);
                read_count += m_input_stream.gcount();
                // Check that we read full images only
                if (m_stream_format != "h264") {
                    uint32_t frames = read_count / m_image_size;
                    if (frames * m_image_size != read_count) {
                        LOG(ERROR) << "Read incomplete frame!";
                    }
                }

                //check if we need to rewind the input stream
                if (m_input_stream.eof()) {
                    LOG(INFO) << "ImageLoadThread::WORK: Finished reading all images -> rewinding";
                    m_input_stream.clear();
                    m_input_stream.seekg(0);
                }
            } while (m_image_size * m_batch_size > read_count);
        }

        m_prev_frame_timestamp = std::chrono::steady_clock::now();
        m_bytes_to_send += read_count;

        bool next_stages_exist = false;

        if (m_stream_format == "h264" || m_stream_format == "h265") {
            messages::mstream::EventBsReady event;
            event.set_supports_backpressure(true);
            event.set_source_id(m_source_id);
            event.mutable_buff()->CopyFrom(*shmem_buff);
            auto flow = event.add_flow();

            flow->set_id(m_flow.id());
            for (uint32_t stage_id : m_flow.pipeline().stage(0).next_stage()) {
                flow->add_stage_id(stage_id);
                next_stages_exist = true;
            }

            LOG(DEBUG) << "Sending event INPUT_BS_READY";
            if (next_stages_exist && !broker_thread::send_msg(m_broker_socket, messages::enums::INPUT_BS_READY, event)) {
                LOG(ERROR) << "Failed sending INPUT_BS_READY";
                return false;
            }

        } else {
            messages::types::EventFrameReady event_frame_ready;
            for (int i = 0; i < m_batch_size; ++i) {
                auto efr = event_frame_ready.add_efr();

                efr->mutable_buff()->CopyFrom(shmem_buff->split(m_image_size));
                efr->mutable_frame_info()->mutable_flow()->set_id(m_flow.id());
                for (uint32_t stage_id : m_flow.pipeline().stage(0).next_stage()) {
                    efr->mutable_frame_info()->mutable_flow()->add_stage_id(stage_id);
                    next_stages_exist = true;
                }
                efr->mutable_frame_info()->mutable_frame()->set_frame_num(m_frame_num++);
                efr->mutable_frame_info()->mutable_frame()->set_is_scaled(true);
                efr->mutable_frame_info()->mutable_frame()->set_width(m_width);
                efr->mutable_frame_info()->mutable_frame()->set_height(m_height);
                efr->mutable_frame_info()->mutable_frame()->set_format(m_stream_format);

                efr->mutable_frame_info()->set_skip_frame(false);
            }
            shmem_buff->drop();
            LOG(DEBUG) << "ImageLoaderThread sending frame numbers: " << event_frame_ready.efr(0).frame_info().frame().frame_num()
                       << ".." << event_frame_ready.efr(m_batch_size - 1).frame_info().frame().frame_num() << " with "
                       << event_frame_ready.efr_size() << " frames";

            if (next_stages_exist &&
                !broker_thread::send_msg(m_broker_socket, messages::enums::DECODED_FRAME_READY, event_frame_ready)) {
                LOG(ERROR) << "Failed sending DECODED_FRAME_READY";
                event_frame_ready.Clear();
                return false;
            }
            event_frame_ready.Clear();
        }

        m_sent_bytes += m_bytes_to_send;
        m_bytes_to_send = 0;
    }

    usleep(1000);
    return true;
}

bool ImageLoadThread::add_source(const messages::types::Source &source)
{
    uint32_t source_id = source.id();

    if (source.type() != messages::enums::StreamType::LOCAL_FILE) {
        LOG(WARNING) << "Got a source not to a local file, ignoring";
        return false;
    }

    auto file_name = source.input();
    m_input_stream.open(file_name, std::ios::binary);
    if (m_input_stream.fail()) {
        LOG(ERROR) << "ERROR: Could not open file " << file_name << " !!\n";
        return false;
    }
    LOG(DEBUG) << "Opened file " << file_name << " for source_id=" << source_id;
    LOG(DEBUG) << "The size of the file is " << getFileSize(m_input_stream);

    messages::types::OptionalSource optional_source;
    if (!source.additional_info().UnpackTo(&optional_source)) {
        LOG(INFO) << "Optional source is not set";
        return true;
    }
    m_width = optional_source.input_width();
    m_height = optional_source.input_height();

    m_frame_rate_us = 0;
    m_bps_sleep_us = 0;

    m_stream_format = getFileExt(file_name);
    if (m_stream_format == "nv12") {
        m_image_size = (m_width * m_height) + (m_width * m_height) / 2;
    } else if (m_stream_format == "rgb") {
        m_image_size = m_width * m_height * 3;
    } else if (m_stream_format == "rgba" || m_stream_format == "rgb4") {
        m_image_size = m_width * m_height * 4;
    } else if (m_stream_format == "h264") {
        m_image_size = SHMEM_BUFF_SIZE;
        m_batch_size = 1;

        m_bps = optional_source.mbps() * 1000 * 1000;
        if (m_bps) {
            m_image_size = m_bps / 8 / 4;
            m_bps_sleep_us = 1000000 / 4;
        }
    } else {
        LOG(FATAL) << "ERROR! ImageLoader: Unsupported input stream (" << m_stream_format
                   << "). supported files: nv12, rgb, rgba, h264";
        return false;
    }

    if (m_stream_format != "h264") {
        m_frame_rate = optional_source.fps();
        if (m_frame_rate)
            m_frame_rate_us = (1000000 / m_frame_rate) * m_batch_size;
    }

    if (m_image_size == 0) {
        LOG(ERROR) << "Image size is 0. Probably didn't set source height/width";
        return false;
    }
    m_load_to_ram = optional_source.load_to_ram();
    if (m_load_to_ram) {
        m_max_ram_size = optional_source.ram_size_mb() * 1024 * 1024;

        uint64_t file_size = getFileSize(m_input_stream);
        if (!file_size) {
            LOG(ERROR) << "File size is 0!";
            return false;
        }
        if (m_max_ram_size >= file_size) {
            m_ram_size = file_size;
        } else {
            int frames_to_read = m_max_ram_size / m_image_size;
            m_ram_size = frames_to_read * m_image_size;
        }
        LOG(DEBUG) << "max_ram_size: " << m_max_ram_size << " Filesize: " << file_size << " m_ram_size = " << m_ram_size;

        m_buffered_file = (char *)malloc(m_ram_size);
        if (!m_buffered_file) {
            LOG(ERROR) << "Failed to allocate memory to buffer file. Size I tried to allocate: " << m_ram_size;
            return false;
        }
        if (!m_input_stream.read(m_buffered_file, m_ram_size)) {
            LOG(ERROR) << "Failed to read file" << file_name;
            return false;
        }
        auto bytes_read = m_input_stream.gcount();
        LOG(DEBUG) << "Read " << bytes_read << " bytes from file to memory";
        m_input_stream.close();
    }

    //init shared memory pool (from producer side)
    m_source_id = source_id;
    int pid = common::os_utils::get_pid();
    int shmkey = (pid << 8) + 100 + source_id;
    m_pool = std::make_shared<imif::common::shmem_pool>(shmkey, m_image_size * 1000);
    if (!m_pool) {
        LOG(FATAL) << "ImageLoadThread::ImageLoadThread-->Failed allocating pool!";
        return false;
    }
    if (!m_pool->attach()) {
        LOG(FATAL) << "ImageLoadThread::ImageLoadThread-->Failed attaching to shmem";
        return false;
    }

    LOG(INFO) << "adding source to ImageLoadThread. Images at size " << m_width << "x" << m_height << " will be read from "
              << file_name;
    return true;
}

bool ImageLoadThread::add_flow(const messages::types::Flow &flow, uint32_t batch_size)
{
    m_flow.CopyFrom(flow);
    set_batch_size(batch_size);
    return true;
}

void ImageLoadThread::set_batch_size(int batch_size)
{
    if (m_stream_format != "h264") {
        m_batch_size = batch_size;
        if (m_frame_rate) {
            m_frame_rate_us = (1000000 / m_frame_rate) * m_batch_size;
        }
    }
}

void ImageLoadThread::reset_stats() { m_sent_bytes = 0; }
