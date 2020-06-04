
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

#include "publisher.h"

using namespace imif;

publisher::publisher() { m_subscribed.clear(); }

void publisher::subscribe(subscriber *sub, const std::string &topic) { m_subscribed[topic].insert(sub); }

void publisher::unsubscribe(subscriber *sub, const std::string &topic)
{
    if (topic == "all") {
        for (auto &subscribed : m_subscribed) {
            subscribed.second.erase(sub);
        }
        return;
    }
    auto subscribed_it = m_subscribed.find(topic);
    if (subscribed_it == m_subscribed.end()) {
        return;
    }
    subscribed_it->second.erase(sub);
}

void publisher::publish(std::string topic, std::string message)
{
    auto subscribed_it = m_subscribed.find(topic);
    if (subscribed_it == m_subscribed.end()) {
        return;
    }
    for (subscriber *sub : subscribed_it->second) {
        sub->publish_event(topic, message);
    }
}
