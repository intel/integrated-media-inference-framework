
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

#include "rtsp_client.h"
#include "easylogging++.h"

using namespace imif;

RtspClientInst::RtspClientInst(int id, std::string uri, std::string dump_path)
{
    LOG(ERROR) << "Attempting to use an unimplemented instance of RtspClientInst. id=" << id;
    m_id = id;
}

int RtspClientInst::getID() { return m_id; }

bool RtspClientInst::setupStream(bool over_tcp) { return false; }

bool RtspClientInst::startStream() { return false; }

bool RtspClientInst::pauseStream() { return false; }

void RtspClientInst::setCodec(std::string codec) { m_codec = codec; }

bool RtspClientInst::openDumpFile(std::string dump_path) { return false; }

void RtspClientInst::closeDumpFile() {}

size_t RtspClientInst::writeToDumpFile(uint8_t *buffer, size_t buffer_size) { return 0; }

void RtspClientInst::reset() {}

void RtspClientInst::setPlaying(bool playing) {}

bool RtspClientInst::getPlaying() { return m_is_playing; }

void RtspClientInst::byeFromServerClbk() {}

int RtspClientInst::sendKeepAlive() { return -1; }

uint8_t *RtspClientInst::getMediaData(std::string media_type, uint8_t *buf, size_t *size, size_t max_size) { return nullptr; }

void RtspClientInst::tearDown() {}
