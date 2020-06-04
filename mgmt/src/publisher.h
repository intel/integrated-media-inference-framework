
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

#ifndef _PUBLISHER_H
#define _PUBLISHER_H

#include <map>
#include <set>
#include <string>

namespace imif {

class subscriber {
public:
    virtual void publish_event(std::string module_name, std::string message) = 0;
};

class publisher {
public:
    publisher();
    void subscribe(subscriber *sub, const std::string &topic);
    void unsubscribe(subscriber *sub, const std::string &topic);
    void publish(std::string topic, std::string message);

private:
    std::map<std::string, std::set<subscriber *>> m_subscribed; // key=topic (submodule name)
};

} // namespace imif

#endif
