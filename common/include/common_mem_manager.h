
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

#ifndef _COMMON_MEM_MANAGER_H_
#define _COMMON_MEM_MANAGER_H_

#include <stdint.h>
#include <stdlib.h>

#include <memory>
#include <messages/proto/shmem_manager.pb.h>
#include <unordered_map>

namespace imif {
namespace common {

class shmem_base {
public:
    shmem_base(int shmkey, size_t size, bool create = false);
    virtual ~shmem_base();
    bool attach();
    size_t get_consecutive_free();
    size_t get_total_free();
    int shmid() { return m_shmid; }
    int shmkey() { return m_shmkey; }
    size_t size() { return m_block_size; }
    uint8_t *ptr() { return m_ptr; }

protected:
    bool alloc(size_t size, size_t *offset);
    bool resize(size_t offset, size_t buff_size, size_t delta);
    bool free(size_t offset, size_t size);
    bool reallocate(size_t old_size, size_t new_size, size_t *offset);
    bool drop(size_t offset, size_t size);
    bool inc_write();
    bool dec_write();
    bool is_valid(size_t offset, size_t write_count, size_t wrap_count);

    uint64_t write_count();
    uint64_t wrap_count();

protected:
    int m_shmkey = -1;
    size_t m_block_size = 0;
    int m_shmid = -1;
    uint8_t *m_ptr = nullptr;
    bool m_is_creator;

private:
    size_t get_min_read_offset();
    size_t get_total_read_count();
    inline size_t calc_write_count();
    bool remove_consumer(int8_t consumer_id);

    int8_t m_consumer_id = 0;
    bool m_is_initialized = false; // shmem has been allocated and we can write to meta.
    bool m_is_synced = false;
};

// forward declaration since both classes use each other
class shmem_pool;
class shmem_buff : public messages::memory::ShmemBuff {
public:
    shmem_buff(std::shared_ptr<shmem_pool> pool, const messages::memory::ShmemBuff &buff);
    shmem_buff(shmem_pool *pool, uint8_t *ptr);
    ~shmem_buff();

    bool reallocate(size_t new_size);
    bool resize(size_t delta);
    bool free();
    messages::memory::ShmemBuff split(size_t split);
    bool drop();

    uint8_t *ptr() { return m_ptr; }
    void freed(bool freed) { m_freed = freed; }
    bool freed() { return m_freed; }

    bool is_valid() { return m_valid; }

private:
    bool init(const messages::memory::ShmemBuff &buff);

    shmem_pool *m_pool = nullptr;
    uint8_t *m_ptr = nullptr;
    bool m_freed = false;
    bool m_valid = false;
};

class shmem_pool : public shmem_base {
public:
    shmem_pool(int shmKey, size_t size, bool producer = true);
    std::shared_ptr<shmem_buff> alloc_buff(size_t size);

    bool resize_buff(shmem_buff *buff, size_t delta);
    bool resize_buff(std::shared_ptr<shmem_buff> buff, size_t delta);

    bool realloc_buff(shmem_buff *buff, size_t new_size);
    bool realloc_buff(std::shared_ptr<shmem_buff> buff, size_t new_size);

    bool free_buff(std::shared_ptr<shmem_buff> buff);
    bool free_buff(size_t offset, size_t size);

    bool drop_buff(shmem_buff *buff);
    bool drop_buff(std::shared_ptr<shmem_buff> buff);

    bool is_valid(size_t offset, size_t write_count, size_t wrap_count);

    bool split_buff();
};

class shmem_buff_factory {
public:
    static std::shared_ptr<shmem_buff> get_buff(const messages::memory::ShmemBuff &buff);
    static std::shared_ptr<shmem_buff> get_buff(uint8_t *buf, int size);
    static bool free_shmem_pool(uint32_t shmemkey);
    thread_local static std::unordered_map<int, std::shared_ptr<shmem_pool>> shmem_pool_map;
    static std::shared_ptr<shmem_pool> get_shmem_pool(int shmkey, size_t shmsize);
};

} // namespace common
} // namespace imif

#endif // _COMMON_MEM_MANAGER_H_
