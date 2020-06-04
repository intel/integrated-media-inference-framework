
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

#ifndef RTSP_CLIENT_H
#define RTSP_CLIENT_H

#include <sys/types.h>

#include <messages/proto/mstream.pb.h>

#include <chrono>
#include <vector>

namespace imif {
class RtspClientInst {
public:
    RtspClientInst(int id, std::string uri, std::string dump_path = std::string());
    ~RtspClientInst() {}
    int getID();

    bool setupStream(bool over_tcp);
    bool startStream();

    bool pauseStream();

    void setCodec(std::string codec);
    bool openDumpFile(std::string dump_path);
    void closeDumpFile();
    size_t writeToDumpFile(uint8_t *buffer, size_t buffer_size);
    void byeFromServerClbk();
    void reset();
    void setPlaying(bool playing);
    bool getPlaying();
    void setStarted(bool started) { m_is_started = (started && m_is_setup); }
    bool getStarted() { return m_is_started; }
    void setSynced(bool synced) { m_synced = synced; }
    bool getSynced() { return m_synced; }
    bool getBye() { return m_signal_bye_from_server; }
    bool getSetup() { return m_is_setup; }
    bool isDumping() { return m_dump_fd != -1; }
    int sendKeepAlive();
    uint8_t *getMediaData(std::string media_type, uint8_t *buf, size_t *size, size_t max_size);
    void tearDown();

private:
    int m_id;
    int m_dump_fd = -1;
    std::shared_ptr<std::ofstream> m_dump_fs;
    std::string m_codec; //h264 / h265
    bool m_signal_bye_from_server = false;
    bool m_is_playing = false;
    bool m_is_started = false;
    bool m_synced = true;
    bool m_is_setup = false;
};
} //namespace imif

#endif // RTSP_CLIENT_H
