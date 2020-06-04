
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

#ifndef _MSTREAM_PUBLISHER_H
#define _MSTREAM_PUBLISHER_H

#include <messages/proto/types.pb.h>

namespace imif {
namespace mstream {
class subscriber {
public:
    virtual void publish_event(uint32_t flow_id, const messages::types::ResultReady &message) = 0;
};

class publisher {
public:
    publisher();
    void subscribe(subscriber *sub, uint32_t flow_id, uint32_t stage_id);
    void unsubscribe(subscriber *sub, uint32_t flow_id, uint32_t stage_id);
    void publish(uint32_t flow_id, uint32_t stage_id, const messages::types::ResultReady &message);

private:
    std::map<uint32_t, std::map<uint32_t, std::set<subscriber *>>> m_subscribed; // key = flow_id, stage_id
};

} // namespace mstream
} // namespace imif
#endif
