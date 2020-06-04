
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

#ifndef _YAML_WRAPPER_H_
#define _YAML_WRAPPER_H_

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <yaml.h>

namespace imif_yaml {

// Those are the supported types of yaml nodes.
// In the current version we do not support anchors, tags and aliases
enum class eNodeType { Undefined, Scalar, Sequence, Map };

class yaml_builder;
class yaml_node {
public:
    yaml_node();
    yaml_node(uint32_t level, eNodeType type = eNodeType::Undefined, const std::string name = "");
    eNodeType type() const { return m_type; }

    operator bool() const { return type() != eNodeType::Undefined; };
    bool operator!() const { return type() == eNodeType::Undefined; };

    yaml_node operator[](const std::string);
    yaml_node operator[](const char *);
    yaml_node operator[](uint32_t);
    yaml_node operator[](int);

    bool is_of_type(eNodeType is_type) const { return type() == is_type; }
    bool is_sequence() const { return is_of_type(eNodeType::Sequence); }
    bool is_scalar() const { return is_of_type(eNodeType::Scalar); }
    bool is_map() const { return is_of_type(eNodeType::Map); }

    std::list<std::shared_ptr<yaml_node>>::iterator begin();
    std::list<std::shared_ptr<yaml_node>>::iterator end();
    std::unordered_map<std::string, std::shared_ptr<yaml_node>>::iterator map_begin();
    std::unordered_map<std::string, std::shared_ptr<yaml_node>>::iterator map_end();
    uint32_t size();

    std::string scalar() const { return is_scalar() ? m_value : std::string(); }
    std::string name() const { return m_name; }
    uint32_t level() const { return m_level; }

    bool remove(const std::string &);
    bool remove(const char *);

private:
    friend yaml_builder;

    uint32_t m_level = 0;
    eNodeType m_type = eNodeType::Undefined;
    std::string m_name = "";
    std::string m_value = "";
    std::list<std::shared_ptr<yaml_node>> m_next_nodes_list;
    std::unordered_map<std::string, std::shared_ptr<yaml_node>> m_next_nodes_map;
};

std::ostream &operator<<(std::ostream &os, const yaml_node &node);

class yaml_builder {
public:
    static yaml_node parse_file(const std::string &);

private:
    static std::shared_ptr<yaml_node> parse_file(yaml_parser_t &parser, yaml_event_type_t trigger_event, uint32_t level,
                                                 std::string key = "");
};
} // namespace imif_yaml

#endif
