
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

#ifndef _COMMON_THREAD_BASE_H_
#define _COMMON_THREAD_BASE_H_

#define THREAD_LOG(a) (LOG(a) << get_name() << ": ")

#include <atomic>
#include <string>
#include <thread>

namespace imif {
namespace common {

class thread_base {
public:
    thread_base() : thread_name(""), should_stop(false), worker_is_running(false) {}
    virtual ~thread_base();
    bool start(std::string name = "");
    void join();
    void stop(bool block = true);
    bool is_running() { return worker_is_running; }
    std::string get_name() { return thread_name; }

    int get_thread_last_error_code() { return thread_last_error_code; }

protected:
    std::string thread_name;
    uint32_t thread_last_error_code = 0;
    bool should_stop = false;

    virtual bool init() = 0;
    virtual bool work() = 0;
    virtual void before_stop() {}
    virtual void on_thread_stop() {}

private:
    void run();
    std::thread worker = std::thread();
    bool worker_is_running = false;
};
} // namespace common
} // namespace imif

#endif // _COMMON_THREAD_BASE_H_
