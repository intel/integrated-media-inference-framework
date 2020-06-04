
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

#include "common_thread_base.h"

#include <easylogging++.h>

using namespace imif::common;

thread_base::~thread_base() { stop(); }

bool thread_base::start(std::string name)
{
    if (!init()) {
        should_stop = true;
        return false;
    }
    if (!name.empty())
        thread_name = name;
    stop();
    should_stop = false;
    worker_is_running = true;
    worker = std::thread(&thread_base::run, this);
    return true;
}

void thread_base::join()
{
    if (worker.joinable()) {
        worker.join();
    }
}

void thread_base::stop(bool block)
{
    should_stop = true;
    before_stop();
    if (block) {
        join();
    }
}

void thread_base::run()
{
    while (!should_stop) {
        if (!work()) {
            LOG(INFO) << "[" << thread_name << "]: work() returned false. Stopping...";
            break;
        }
    }
    on_thread_stop();
    worker_is_running = false;
}
