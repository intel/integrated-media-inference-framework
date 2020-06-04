
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

#ifndef _MGMT_LIB_H
#define _MGMT_LIB_H

#include "common_logging.h"
#include "yaml_wrapper.h"
#include <grpcpp/grpcpp.h>
#include <messages/grpc/mgmt_ext_services.grpc.pb.h>
#include <messages/proto/mgmt.pb.h>
#include <messages/proto/mgmt_ext.pb.h>

#include <arpa/inet.h>
#include <map>
#include <memory>
#include <string>
#include <thread>

namespace imif {
namespace mgmt {

using CallbackFunc = std::function<void(const messages::mgmt_ext::Event &)>;

class management_client {
public:
    management_client();
    ~management_client();

    /**
     * @brief Connect to the imif management server via grpc.
     * 
     * @param host_or_ip_str The hostname or the ip address of the server
     * @param port_str The port the server is listening on
     * @return true connection successful
     * @return false connection failed
     */

    bool connect(std::string &host_or_ip_str, std::string &port_str);

    /**
     * @brief Disconnect from imif management server.
     * 
     */
    void disconnect();

    /**
     * @brief Send a ping to the server to verify connection is healthy
     * 
     * @return true Received response to the ping
     * @return false Sending of ping failed or received improper response.
     */
    bool ping();

    /**
     * @brief Request a module to be reset
     * 
     * @param module_name The module to be reset. Send the string "all" to reset all modules.
     * @param wgid The ID of the workgroup that on which the module will be reset.
     *             Send -1 as wgid to reset the module on all workgroups
     * @return true on success
     * @return false on failure
     */
    bool send_reset(std::string module_name, int64_t wgid);

    /**
     * @brief Enable or disable a module
     * 
     * @param module_name The name of the module. Send the string "all" to set all modules.
     * @param enabled a boolean stating if the module is to be enabled or disabled
     * @param wgid The ID of the workgroup on which to operate, send -1 to operate on all workgroups
     * @param sub_module The submodule on which to operate. Leave empty if not necessary
     * @return true on success
     * @return false on failure
     */
    bool set_module_state(std::string module_name, bool enabled, int64_t wgid, std::string sub_module = std::string());

    /**
     * @brief Get a list of all modules, and for each module if it's been registered with the management, and if it has been enabled
     * 
     * @param all_modules_status Output parameter - will contain the list after execution.
     */
    void get_module_list(messages::mgmt_ext::AllModulesStatus *all_modules_status);

    /**
     * @brief List all objects of type 'item_name' on 'module' in the workgroup specified by 'wgid'.
     * 
     * @param item_name A string specifying what item to request. Can be: config, source, flow or workgroup.
     * @param module The module to be probed. Use the string "all" to probe all modules.
     * @param list_response Output parameter - will contain the list of requested items.
     * @param wgid The workgroup to be probed. Use -1 to probe all workgroups.
     */
    void list(std::string item_name, std::string module, imif::messages::mgmt_ext::ListResponse *list_response, int64_t wgid);

    /**
     * @brief list the object with id 'id' of type 'item_name' on 'module' in the workgroup specified by 'wgid'.
     * 
     * @param item_name A string specifying what item to request. Can be: config, source, flow or workgroup.
     * @param module The module to be probed. Use the string "all" to probe all modules.
     * @param id The id of the object to show
     * @param list_response  Output parameter - will contain the requested item, if it exists
     * @param wgid The workgroup to be probed. Use -1 to probe all workgroups.
     */
    void list(std::string item_name, std::string module, uint32_t id, imif::messages::mgmt_ext::ListResponse *list_response,
              int64_t wgid);

    /**
     * @brief Register a callback function to be called for each message we're subscribed to.
     * 
     * @param callback the callback function.
     */
    void register_listener_callback(CallbackFunc callback);

    /**
     * @brief Subscribe to receive status messages. Each message will call the callback registered by 'register_listener_callback()'
     * 
     * @param topic A string specifying what statistics we're subscribing to. Possible topics: mstream, mdecode, inference, tcp_sender
     * @param subscribe A boolean specifying if we want to subscribe or unsubscribe
     * @param wgid  The ID of the workgroup we want to subscribe to. Use -1 to subscribe to all workgroups.
     * @return true for success
     * @return false for failure
     */
    bool subscribe(std::string topic, bool subscribe, int64_t wgid);

    /**
     * @brief Adds a workgroup
     * 
     * @param host_or_ip_str The hostname or IP adress of the workgroup
     * @param port The port used by the workgroup
     * @param wgname An alias that can be used to refer to the workgroup in the future
     * @return int64_t An ID identifying the workgroup for future reference. Can be used interchangibly to the wgname.
     */
    int64_t add_workgroup(std::string &host_or_ip_str, uint32_t port, std::string wgname);

    /**
     * @brief Add a source
     * 
     * @param source The source to add
     * @param wgid The workgroup to add the source to
     * @return true on success
     * @return false on failure
     */
    bool add_source(const imif::messages::types::Source &source, int64_t wgid);
    /**
     * @brief 
     * 
     * @param source_id The ID of the source to remove
     * @param wgid The workgroup to add the source to
     * @return true on success
     * @return false on failure
     */
    bool remove_source(uint32_t source_id, int64_t wgid);

    /**
     * @brief Add a flow
     * 
     * @param flow The flow to add
     * @param wgid  The workgroup to add the flow to
     * @return true on success
     * @return false on failure
     */
    bool add_flow(imif::messages::types::Flow &flow, int64_t wgid);

    /**
     * @brief Remove a flow
     * 
     * @param flow_id  The ID of the flow to remove
     * @param wgid The workgroup to remove the flow from
     * @return true on success
     * @return false on failure
     */
    bool remove_flow(uint32_t flow_id, int64_t wgid);

    /**
     * @brief Add a config
     * 
     * @param add_config The config to add
     * @param wgid the workgroup to add the config to
     * @return true on success
     * @return false on failure
     */
    bool add_config(imif::messages::mgmt::AddConfig &add_config, int64_t wgid);

    /**
     * @brief Remove a config
     * 
     * @param cfg_id The ID of the config to remove
     * @param module_name The module on which the config is to be removed
     * @param wgid The workgroup on which the config will be removed
     * @return true on success
     * @return false on failure
     */
    bool remove_config(uint32_t cfg_id, std::string module_name, int64_t wgid);

    /**
     * @brief Send command to an imif module
     * 
     * @param command Message containing the target module id, and the command. Possible commands: pnpt::eCommands::START, pnpt::eCommands::STOP
     * @param wgid The workgroup to execute the command on
     * @return true on success
     * @return false on failure
     */
    bool command(const messages::types::Command &command, int64_t wgid);

    /**
     * @brief Set the log level of a module
     * 
     * @param module_name The name of the module to set the loglevel on. Use the string "all" for all modules
     * @param log_lvl an enum specifying what log levels should be written to logs
     * @param new_state a boolean specifying if the messages on this log level should be written or not
     * @return true on success
     * @return false on failure
     */
    bool set_log_level(std::string module_name, imif::common::eLogLevel log_lvl, bool new_state);

    /**
     * @brief Start a source
     * 
     * @param source_id The ID of the source to start
     * @param wgid The workgroup to start the source on
     * @return true on success
     * @return false on failure
     */
    bool start_source(uint32_t source_id, int64_t wgid);

    /**
     * @brief load a .yaml file, adding all the sources, flows and configs in it.
     * 
     * @param filename The path to the yaml file
     * @param wgid The workgroup to load the yaml file on
     * @return true on success
     * @return false on failure
     */
    bool load_yaml(std::string filename, int64_t wgid);

    /**
     * @brief Get the workgroup id
     * 
     * @param name The name of the workgroup.
     * @return int64_t The workgroup ID.
     */
    int64_t get_workgroup_id(std::string name);

    /**
     * @brief Give a workgroup an alias 
     * 
     * @param wgid The workgroup ID
     * @param name A name by which the workgroup will be accessible.
     * @return true on success
     * @return false on failure
     */
    bool set_workgroup_name(int64_t wgid, std::string name);

    /**
     * @brief copy files from imif mgmt server to module.
     * 
     * @param filename the file to copy
     * @param module_name the name of the module
     * @param wgid The workgroup the module is on
     * @return true on success
     * @return false on failure
     */
    bool push(const std::string &filename, std::string module_name, int64_t wgid);

    /**
     * @brief copy files from imif mgmt server to module.
     * 
     * @param filename the file to copy
     * @param module_name the name of the module
     * @param wgid The workgroup the module is on
     * @return true on success
     * @return false on failure
     */
    bool pull(std::string module_name, int64_t wgid);

private:
    bool check_error(grpc::Status &status);
    bool listen();
    void stop_listen();
    uint32_t request_id();
    // change to dispatch_events(callable), should do the same if called as dispatch_events(&print())
    void event_dispatch();
    bool mstream_add_config(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool mdecode_add_config(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool inference_add_config(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool add_source(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool custom_add_config(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool add_flow(imif_yaml::yaml_node &yaml_config, int64_t wgid);
    bool remove_item(uint32_t item_id, std::string item_name, std::string module_name, int64_t wgid);
    bool push_file(const std::string &filename, void *tag);
    bool read_file_chunk(const std::string &filename, char *buffer, int64_t &file_pos, int64_t &length, bool &is_done);

    CallbackFunc m_listener_callback = nullptr;

    std::shared_ptr<grpc::Channel> m_channel = nullptr;
    std::unique_ptr<services::mgmt_ext::MgmtLibrary::Stub> m_stub = nullptr;

    // All these belong to the listener:
    std::shared_ptr<grpc::CompletionQueue> m_cq = nullptr;
    std::unique_ptr<::grpc::ClientAsyncReader<messages::mgmt_ext::Event>> m_event_reader = nullptr;
    std::shared_ptr<grpc::ClientContext> m_listener_context = nullptr;
    std::thread m_event_dispatch_thread = std::thread();
    std::atomic_bool m_running{};
    uint32_t m_listener_id = 0;
    const uint64_t MAX_CHUNK_SIZE = 32768;
};
} // namespace mgmt
} // namespace imif
#endif
