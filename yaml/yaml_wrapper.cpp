
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

#include "yaml_wrapper.h"

#include "common_logging.h"

#include <stdio.h>

using namespace imif_yaml;

static std::string print_event_type(yaml_event_type_t event)
{
    if (event == YAML_SEQUENCE_START_EVENT) {
        return "YAML_SEQUENCE_START_EVENT";
    } else if (event == YAML_SEQUENCE_END_EVENT) {
        return "YAML_SEQUENCE_END_EVENT";
    } else if (event == YAML_MAPPING_START_EVENT) {
        return "YAML_MAPPING_START_EVENT";
    } else if (event == YAML_MAPPING_END_EVENT) {
        return "YAML_MAPPING_END_EVENT";
    } else if (event == YAML_SCALAR_EVENT) {
        return "YAML_SCALAR_EVENT";
    } else if (event == YAML_DOCUMENT_START_EVENT) {
        return "YAML_DOCUMENT_START_EVENT";
    } else if (event == YAML_DOCUMENT_END_EVENT) {
        return "YAML_DOCUMENT_END_EVENT";
    } else if (event == YAML_STREAM_START_EVENT) {
        return "YAML_STREAM_START_EVENT";
    } else if (event == YAML_STREAM_END_EVENT) {
        return "YAML_STREAM_END_EVENT";
    }

    return "UNKNOWN EVENT";
}

static std::string indent(uint32_t level)
{
    std::stringstream ss;
    for (uint32_t i = 0; i < level; i++) {
        ss << "   ";
    }
    return ss.str();
}

eNodeType get_node_type(yaml_event_type_t trigger_event)
{
    if (trigger_event == YAML_SEQUENCE_START_EVENT)
        return eNodeType::Sequence;
    else if (trigger_event == YAML_SCALAR_EVENT)
        return eNodeType::Scalar;
    else if (trigger_event == YAML_MAPPING_START_EVENT)
        return eNodeType::Map;

    return eNodeType::Undefined;
}

// parse_file is a recursive function. It starts an iteration for each new node needed to be constructed
std::shared_ptr<yaml_node> yaml_builder::parse_file(yaml_parser_t &parser, yaml_event_type_t trigger_event, uint32_t level,
                                                    std::string key)
{
    eNodeType node_type = get_node_type(trigger_event);

    auto event = std::shared_ptr<yaml_event_t>(new yaml_event_t, [](yaml_event_t *obj) {
        if (obj)
            yaml_event_delete(obj);
    });
    if (!event) {
        LOG(ERROR) << "Failed allocating event sctruct!";
        return nullptr;
    }

    // Create the current node
    std::shared_ptr<yaml_node> node = std::make_shared<yaml_node>(level, node_type, key);
    if (!node) {
        LOG(ERROR) << "Failed allocation new node!";
        return nullptr;
    }
    yaml_event_type_t event_type = YAML_NO_EVENT;
    do {
        // Get next yaml event from yaml parser
        if (!yaml_parser_parse(&parser, event.get())) {
            LOG(ERROR) << "Failed parsing event!";
            return nullptr;
        }
        event_type = event->type;
        switch (event_type) {
        case YAML_DOCUMENT_START_EVENT:
        case YAML_DOCUMENT_END_EVENT:
        case YAML_STREAM_START_EVENT:
        case YAML_STREAM_END_EVENT: {
            // Those events mark the start and begining of the yaml file. we expect them only on level 0
            if (level != 0) {
                LOG(ERROR) << "Recived " << print_event_type(event_type) << " on level " << level;
                return nullptr;
            }
        } break;
        case YAML_SCALAR_EVENT: {
            // When we get a YAML_SCALAR_EVENT it might mean 1 of 3 things:
            // 1. SCALAR_event after another SCALAR_event -> the first event was a name and now we got a value
            // 2. SCALAR_event after SEQUENCE_START -> we have a sequence of scalars -> name: [value1, value2]
            // 3. SCALAR_event after MAP_STARTS -> we got a name of a new entry. This entry might be a map, sequence or scalar.
            if (trigger_event == YAML_SCALAR_EVENT) {
                // Previous event was scalar, so we have here a value
                node->m_value = std::string((char *)event->data.scalar.value);
                return node;
            } else if (trigger_event == YAML_SEQUENCE_START_EVENT) {
                // Previous event was SEQUENCE_START so we have a sequence of valuses.
                // Pust this scalar value to the list
                auto seq_node = std::make_shared<yaml_node>(level + 1, eNodeType::Scalar);
                if (!seq_node) {
                    LOG(ERROR) << "Failed allocating yaml_node!";
                    return nullptr;
                }
                seq_node->m_value = std::string((char *)event->data.scalar.value);
                node->m_next_nodes_list.push_back(seq_node);
            } else if (trigger_event == YAML_MAPPING_START_EVENT) {
                // We have a map of some sort. We have here a SCALAR event.
                // It may either a name of some scalar value, a name of a map or a name of a sequence.
                // We start a new itteration and see what event we will get next
                std::string node_name = std::string((char *)event->data.scalar.value);
                auto next_node = parse_file(parser, YAML_SCALAR_EVENT, level, node_name);
                if (!next_node) {
                    LOG(ERROR) << "Failed parsing";
                    return nullptr;
                }

                node->m_next_nodes_map[node_name] = next_node;
            } else {
                LOG(ERROR) << "Unexpected event " << print_event_type(event_type) << "  with trigger "
                           << print_event_type(trigger_event);
                return nullptr;
            }
        } break;
        case YAML_SEQUENCE_START_EVENT: {
            if (level == 0) {
                node->m_type = eNodeType::Sequence;
                trigger_event = YAML_SEQUENCE_START_EVENT;
            }

            if (trigger_event == YAML_SCALAR_EVENT) {
                // When the previous event was scalar, it only marked the name of the sequece,
                // no need to start new iteration. just mark the type of the node and get the next event.
                node->m_type = eNodeType::Sequence;
                trigger_event = YAML_SEQUENCE_START_EVENT;
                break;
            }

            auto next_node = parse_file(parser, YAML_SEQUENCE_START_EVENT, level + 1, key);
            if (!next_node) {
                LOG(ERROR) << "Failed parsing!";
                return nullptr;
            }

            // We finished parsing the next node, let's put it in the right place.
            if (node->m_type == eNodeType::Map) {
                node->m_next_nodes_map[next_node->m_name] = next_node;
            } else if (node->m_type == eNodeType::Sequence) {
                node->m_next_nodes_list.push_back(next_node);
            } else {
                return node;
            }
        } break;
        case YAML_SEQUENCE_END_EVENT: {
            if (trigger_event != YAML_SEQUENCE_START_EVENT) {
                LOG(ERROR) << "Unexpected event " << print_event_type(event_type) << "  with trigger "
                           << print_event_type(trigger_event);
                return nullptr;
            }
            return node;
        }
        case YAML_MAPPING_START_EVENT: {
            if (level == 0) {
                node->m_type = eNodeType::Map;
                trigger_event = YAML_MAPPING_START_EVENT;
            }

            if (trigger_event == YAML_SCALAR_EVENT) {
                // When the previous event was scalar, it only marked the name of the map,
                // no need to start new iteration. just mark the type of the node and get the next event.
                node->m_type = eNodeType::Map;
                trigger_event = YAML_MAPPING_START_EVENT;
                break;
            }
            auto next_node = parse_file(parser, YAML_MAPPING_START_EVENT, level + 1);
            if (!next_node) {
                LOG(ERROR) << "Failed parsing!";
                return nullptr;
            }
            if (trigger_event == YAML_MAPPING_START_EVENT) {
                node->m_next_nodes_map[next_node->m_name] = next_node;
            } else if (trigger_event == YAML_SEQUENCE_START_EVENT) {
                node->m_next_nodes_list.push_back(next_node);
            } else {
                return node;
            }
        } break;
        case YAML_MAPPING_END_EVENT: {
            if (trigger_event != YAML_MAPPING_START_EVENT) {
                LOG(ERROR) << "Unexpected event " << print_event_type(event_type) << "  with trigger "
                           << print_event_type(trigger_event);
                return nullptr;
            }
            return node;
        }
        default: {
            LOG(DEBUG) << indent(level) << "Unknown event: " << event->type;
            return nullptr;
        }
        }

        yaml_event_delete(event.get());
    } while (event_type != YAML_STREAM_END_EVENT);

    // We get here only on the end of the file.
    // Since we start a new node from root level, the root level is just a stub and holds no information.
    // So, we skip the root node and return the next.
    if (node->m_type == eNodeType::Map)
        return node->m_next_nodes_map.begin()->second;
    if (node->m_type == eNodeType::Sequence)
        return node->m_next_nodes_list.front();
    return node;
}

yaml_node yaml_builder::parse_file(const std::string &file_name)
{
    yaml_parser_t parser;
    if (yaml_parser_initialize(&parser) == 0) {
        LOG(ERROR) << "Failed initializing parser";
        return yaml_node();
    }

    std::ifstream fs(file_name);
    if (!fs.is_open()) {
        LOG(ERROR) << "Failed opening file " << file_name;
        return yaml_node();
    }

    std::stringstream ss;
    ss << fs.rdbuf();

    yaml_parser_set_input_string(&parser, (const unsigned char *)ss.str().c_str(), ss.str().size());

    auto node = parse_file(parser, YAML_NO_EVENT, 0, "root");

    yaml_parser_delete(&parser);

    fs.close();

    if (!node) {
        LOG(ERROR) << "Failed parsing yaml file " << file_name;
        return yaml_node();
    }

    return *node;
}

yaml_node::yaml_node()
{
    m_next_nodes_map.clear();
    m_next_nodes_list.clear();
}

yaml_node::yaml_node(uint32_t level, eNodeType type, const std::string name) : m_level(level), m_type(type), m_name(name)
{
    m_next_nodes_map.clear();
    m_next_nodes_list.clear();
}

yaml_node yaml_node::operator[](const std::string key)
{
    if (m_type == eNodeType::Map) {
        auto elem = m_next_nodes_map.find(key);
        if (elem != m_next_nodes_map.end()) {
            return *elem->second;
        }
    }
    return yaml_node();
}

yaml_node yaml_node::operator[](const char *key) { return (*this)[std::string(key)]; }

yaml_node yaml_node::operator[](uint32_t index)
{
    if (m_type == eNodeType::Sequence) {
        if (index < m_next_nodes_list.size()) {
            auto it = m_next_nodes_list.begin();
            std::advance(it, index);
            return *(*it);
        }
    }
    return yaml_node();
}

yaml_node yaml_node::operator[](int index) { return (*this)[(uint32_t)index]; }

std::list<std::shared_ptr<yaml_node>>::iterator yaml_node::begin()
{
    if (is_sequence()) {
        return m_next_nodes_list.begin();
    }
    return m_next_nodes_list.end();
}

std::list<std::shared_ptr<yaml_node>>::iterator yaml_node::end() { return m_next_nodes_list.end(); }

std::unordered_map<std::string, std::shared_ptr<yaml_node>>::iterator yaml_node::map_begin()
{
    if (is_map()) {
        return m_next_nodes_map.begin();
    }
    return m_next_nodes_map.end();
}

std::unordered_map<std::string, std::shared_ptr<yaml_node>>::iterator yaml_node::map_end() { return m_next_nodes_map.end(); }

uint32_t yaml_node::size()
{
    if (is_sequence())
        return m_next_nodes_list.size();
    if (is_map())
        return m_next_nodes_map.size();
    return 0;
}

bool yaml_node::remove(const std::string &key)
{
    if (!is_map())
        return false;
    m_next_nodes_map.erase(key);
    return true;
}

bool yaml_node::remove(const char *key) { return remove(std::string(key)); }

std::ostream &imif_yaml::operator<<(std::ostream &os, const yaml_node &const_node)
{
    yaml_node node = const_node;
    std::stringstream ss;
    if (node.type() == eNodeType::Scalar) {
        if (!node.name().empty())
            ss << node.name() << ": ";
        if (!node.scalar().empty())
            ss << node.scalar();
    } else {
        if (!node.name().empty())
            ss << node.name() << ": ";
    }
    if (!ss.str().empty())
        os << indent(node.level()) << ss.str() << std::endl;

    for (auto elem : node) {
        if (elem->is_scalar())
            os << indent(node.level()) << "-" << std::endl;
        os << *elem;
    }
    for (auto elem = node.map_begin(); elem != node.map_end(); elem++) {
        os << *elem->second;
    }

    return os;
}
