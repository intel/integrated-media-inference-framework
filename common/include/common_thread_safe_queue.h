
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

#ifndef _THREAD_SAFE_QUEUE_H_
#define _THREAD_SAFE_QUEUE_H_

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>

namespace imif {
namespace common {

template <typename T> class thread_safe_queue {
public:
    T pop(bool block = true, int timeout = 0)
    {
        std::unique_lock<std::mutex> mlock(mutex_, std::defer_lock);

        if (block) {
            mlock.lock();
            while (queue_.empty()) {
                if (!timeout) {
                    cond_.wait(mlock);
                    if (queue_.empty()) {
                        return T();
                    }

                } else {
                    if (cond_.wait_for(mlock, std::chrono::milliseconds(timeout)) == std::cv_status::timeout) {
                        return T();
                    }
                }
            }
        } else {
            if (!mlock.try_lock() || queue_.empty()) {
                return T();
            }
        }

        auto item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    bool push(const T &item, bool block = true)
    {
        std::unique_lock<std::mutex> mlock(mutex_, std::defer_lock);

        if (block) {
            mlock.lock();
        } else if (!mlock.try_lock()) {
            return false;
        }

        queue_.push(item);
        mlock.unlock();
        cond_.notify_one();

        return true;
    }

    bool push(T &&item, bool block = true)
    {
        std::unique_lock<std::mutex> mlock(mutex_, std::defer_lock);

        if (block) {
            mlock.lock();
        } else if (!mlock.try_lock()) {
            return false;
        }

        queue_.push(std::move(item));
        mlock.unlock();
        cond_.notify_one();

        return true;
    }

    bool empty()
    {
        std::unique_lock<std::mutex> mlock(mutex_);
        return queue_.empty();
    }

    void clear()
    {
        std::unique_lock<std::mutex> mlock(mutex_);
        while (!queue_.empty()) {
            queue_.pop();
        }
    }

    void unblock()
    {
        // Unblock any client that is blocked on the pop() method
        cond_.notify_one();
    }

private:
    std::queue<T> queue_;
    std::condition_variable cond_;
    mutable std::mutex mutex_;
};

} // namespace common
} // namespace imif

#endif // _THREAD_SAFE_QUEUE_H_
