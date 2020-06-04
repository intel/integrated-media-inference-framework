
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

#include "common_mem_manager.h"

#include <easylogging++.h>

#include <string.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <algorithm>
#include <limits>

namespace imif {
namespace common {

const uint16_t MAX_CONSUMERS = 10;
typedef struct {
    uint64_t read_offset;
    uint64_t read_count;
    int8_t next_consumer;
    int8_t prev_consumer;
} consumer_t;

struct shmem_meta {
    bool lock;
    consumer_t consumers[MAX_CONSUMERS];
    uint64_t write_offset;
    uint64_t deepest_write;
    uint64_t write_count;
    uint64_t wrap_count;
    uint8_t number_of_consumers;
    int8_t first_unused_consumer;
    int8_t first_used_consumer;
};

class lock_raii {
public:
    lock_raii(bool *bit) : m_bit(bit)
    {
        while (!__sync_bool_compare_and_swap(m_bit, 0, 1)) {
        }
        released = false;
    }
    ~lock_raii() { release(); }
    void release()
    {
        if (!released) {
            *m_bit = 0;
            released = true;
        }
    }

private:
    bool *m_bit;
    bool released;
};

#define GET_META_PTR(PTR, BLOCKSIZE) (shmem_meta *)((uint8_t *)PTR + BLOCKSIZE)
#define GET_META GET_META_PTR(m_ptr, m_block_size)

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Implementation ///////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

shmem_base::shmem_base(int shmkey, size_t size, bool create) : m_shmkey(shmkey), m_block_size(size), m_is_creator(create) {}

shmem_base::~shmem_base()
{
    LOG(DEBUG) << "~shmem_base: m_is_creator=" << m_is_creator << " shmkey=" << std::hex << m_shmkey << std::dec
               << " m_shmid=" << m_shmid;
    if (!m_ptr) {
        LOG(ERROR) << "Can't detach from the shared memory - ptr = nullptr";
        return;
    }

    if (!m_is_creator) {
        remove_consumer(m_consumer_id);
    }

    if (shmdt(m_ptr) < 0) {
        LOG(ERROR) << "Failed detaching from shared memory: " << strerror(errno);
        return;
    }
    m_ptr = nullptr;

    if (!m_is_creator) {
        return;
    }

    if (m_shmid < 0) {
        LOG(ERROR) << "Can't destroy the shmem - shmid < 0";
    }
    if (shmctl(m_shmid, IPC_RMID, NULL) < 0) {
        LOG(ERROR) << "Failed removing shared memory id=" << m_shmid << " : " << strerror(errno);
        return;
    }
}

bool shmem_base::attach()
{
    int flags = S_IRWXU;
    if (m_is_creator) {
        flags |= int(IPC_CREAT | IPC_EXCL);
    }
    // Attach to a buffer with the desired size + meta_data space + 1 byte for full indication
    m_shmid = shmget(m_shmkey, m_block_size + sizeof(shmem_meta), flags);
    if (m_shmid < 0) {
        LOG(ERROR) << "Failed creating shmem with key=" << m_shmkey << ": " << strerror(errno);
        return false;
    }

    LOG(DEBUG) << "Attach shmkey=0x" << std::hex << m_shmkey << std::dec << " Got shmid=" << m_shmid
               << " m_block_size=" << std::to_string(m_block_size);

    m_ptr = (uint8_t *)shmat(m_shmid, NULL, 0);
    if (m_ptr == (void *)-1) {
        m_ptr = nullptr;
        LOG(ERROR) << "Failed attaching to shmem: " << strerror(errno);
        return false;
    }

    if (m_is_creator) {
        // META initialization:
        if (m_is_initialized) {
            LOG(ERROR) << "Creator called attach twice!";
            return false;
        }

        shmem_meta *meta = GET_META;
        for (int i = 0; i < MAX_CONSUMERS - 1; ++i) {
            meta->consumers[i].next_consumer = i + 1;
            meta->consumers[i + 1].prev_consumer = i;
        }
        meta->consumers[MAX_CONSUMERS - 1].next_consumer = -1;
        meta->consumers[0].prev_consumer = -1;

        meta->number_of_consumers = 0;

        meta->first_unused_consumer = 0;
        meta->first_used_consumer = -1;

    } else {
        shmem_meta *meta = GET_META;
        lock_raii lock(&meta->lock);
        int8_t consumer_id = meta->first_unused_consumer;
        if (-1 == consumer_id) {
            LOG(ERROR) << "Couldnt find unattached consumer slot";
            return false;
        }

        m_consumer_id = consumer_id;

        // remove consumer_id from list of unallocated consumers:
        int8_t new_head = meta->consumers[consumer_id].next_consumer;
        if (-1 != new_head) {
            meta->consumers[new_head].prev_consumer = -1;
        }
        meta->first_unused_consumer = new_head;

        // put consumer_id into list of allocated consumers;
        int8_t old_head = meta->first_used_consumer;
        meta->consumers[consumer_id].next_consumer = old_head;
        if (-1 != old_head) {
            meta->consumers[old_head].prev_consumer = consumer_id;
        }
        meta->consumers[consumer_id].prev_consumer = -1;
        meta->first_used_consumer = consumer_id;

        // Initialize offsets
        meta->consumers[consumer_id].read_offset = __sync_fetch_and_add(&meta->write_offset, 0);
        meta->consumers[consumer_id].read_count = __sync_fetch_and_add(&meta->write_count, 0);

        meta->number_of_consumers++;
        LOG(INFO) << "Got consumer_id " << std::to_string(m_consumer_id);
    }

    m_is_initialized = true;
    return true;
}

size_t shmem_base::get_consecutive_free()
{
    size_t headFree = 0;
    size_t tailFree = 0;

    shmem_meta *meta = GET_META;
    size_t read_offset = get_min_read_offset();
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);

    if ((read_offset == write_offset) && (get_total_read_count() != calc_write_count())) {
        return 0;
    }

    if (read_offset > write_offset) {
        headFree = read_offset - write_offset;
    } else {
        tailFree = m_block_size - write_offset;
        headFree = read_offset;
    }

    return std::max(headFree, tailFree);
}

size_t shmem_base::get_total_free()
{
    size_t headFree = 0;
    size_t tailFree = 0;

    shmem_meta *meta = GET_META;
    size_t read_offset = get_min_read_offset();
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);

    if ((read_offset == write_offset) && (get_total_read_count() != calc_write_count())) {
        return 0;
    }

    if (read_offset > write_offset) {
        headFree = read_offset - write_offset;
    } else {
        tailFree = m_block_size - write_offset;
        headFree = read_offset;
    }

    return headFree + tailFree;
}

bool shmem_base::alloc(size_t size, size_t *offset)
{
    if (size > m_block_size) {
        LOG(ERROR) << "Can't allocate buff - size is larger than block size";
        return false;
    }
    if (!offset) {
        LOG(ERROR) << "Offset is null!";
        return false;
    }

    shmem_meta *meta = GET_META;
    size_t read_offset = get_min_read_offset();
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);

    // Check that there is sufficient memory
    if ((read_offset == write_offset) && (get_total_read_count() != calc_write_count())) {
        return false;
    }

    if ((meta->deepest_write) && (write_offset >= read_offset)) {
        meta->deepest_write = 0;
    }

    // If read_offset > write_offset -> maxAllocateable = read-write
    if ((read_offset > write_offset) && (write_offset + size > read_offset)) {
        LOG(ERROR) << "Not enough memory for allocation!"
                   << " shmkey=" << std::hex << m_shmkey << std::dec << " size=" << std::to_string(size)
                   << " write_offset=" << write_offset << " read_offset=" << read_offset
                   << " deepest_write=" << meta->deepest_write;
        return false;
    } else if (write_offset + size > m_block_size) {
        if (size > read_offset) {
            LOG(ERROR) << "Not enough memory for allocation!"
                       << " shmkey=" << std::hex << m_shmkey << std::dec << " size=" << std::to_string(size)
                       << " write_offset=" << write_offset << " read_offset=" << read_offset
                       << " deepest_write=" << meta->deepest_write;
            return false;
        }
        // Wraparound
        meta->deepest_write = write_offset;
        LOG(DEBUG) << "Wrap around. meta->deepest_write=" << std::to_string(write_offset);
        write_offset = 0;
        meta->wrap_count++;
    }

    *offset = write_offset;

    write_offset += size;
    __sync_bool_compare_and_swap(&meta->write_offset, meta->write_offset, write_offset);
    __sync_add_and_fetch(&meta->write_count, 1);

    LOG(DEBUG) << "Allocated buff for size=" << std::to_string(size) << " at offset=" << std::to_string(*offset)
               << " shmkey=" << std::hex << m_shmkey << std::dec << " write_offset=" << write_offset
               << " deepest_write=" << meta->deepest_write << " write count=" << meta->write_count
               << " read offset=" << read_offset;
    return true;
}

bool shmem_base::resize(size_t offset, size_t buff_size, size_t delta)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't resize buff from non creator pool";
        return false;
    }

    shmem_meta *meta = GET_META;
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);
    size_t read_offset = get_min_read_offset();

    // Check that there were no chunks allocated after this one.
    bool lastChunk = (write_offset == (offset + buff_size));
    if (!lastChunk) {
        LOG(ERROR) << "Can't resize the buff - another chuck was allocated after it!";
        return false;
    }

    if ((read_offset > write_offset) && (write_offset + delta > read_offset)) {
        LOG(ERROR) << "Not enough memory for resize!";
        return false;
    } else if (write_offset + delta > m_block_size) {
        LOG(ERROR) << "Not enough memory for resize!";
        return false;
    }

    if (meta->deepest_write == write_offset) {
        __sync_fetch_and_add(&meta->deepest_write, delta);
    }
    __sync_fetch_and_add(&meta->write_offset, delta);

    return true;
}

bool shmem_base::reallocate(size_t old_size, size_t new_size, size_t *offset)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't resize buff from non creator pool";
        return false;
    }

    shmem_meta *meta = GET_META;
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);
    size_t read_offset = get_min_read_offset();

    // Check that there were no chunks allocated after this one.
    bool lastChunk = (write_offset == (*offset + old_size));
    if (!lastChunk) {
        LOG(ERROR) << "Can't reallocate the buff - another chuck was allocated after it! shmkey=" << std::hex << m_shmkey
                   << std::dec;
        return false;
    }

    ssize_t size_delta = new_size - old_size;

    if (read_offset > write_offset) {
        return resize(*offset, old_size, size_delta);
    } else if ((read_offset <= write_offset) && (*offset + new_size < m_block_size)) {
        // we can add the delta at the end of the buffer
        return resize(*offset, old_size, size_delta);
    }

    size_t old_offset = *offset;

    if (!alloc(new_size, offset)) {
        return false;
    }

    if (old_offset + old_size == meta->deepest_write) {
        meta->deepest_write = old_offset;
    }

    return true;
}

bool shmem_base::drop(size_t offset, size_t size)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't drop buff from non creator pool";
        return false;
    }

    shmem_meta *meta = GET_META;
    size_t write_offset = meta->write_offset;

    bool lastChunk = (write_offset == (offset + size));
    if (!lastChunk) {
        LOG(ERROR) << "Can't drop the buff - another chunk was allocated after it! shmkey=" << std::hex << m_shmkey << std::dec;
        return false;
    }

    if (offset + size == meta->deepest_write) {
        meta->deepest_write = offset;
    }

    meta->write_offset = offset;
    dec_write();
    return true;
}

bool shmem_base::inc_write()
{
    shmem_meta *meta = GET_META;
    __sync_add_and_fetch(&meta->write_count, 1);
    return true;
}

bool shmem_base::dec_write()
{
    shmem_meta *meta = GET_META;
    __sync_sub_and_fetch(&meta->write_count, 1);
    return true;
}

bool shmem_base::free(size_t offset, size_t size)
{
    shmem_meta *meta = GET_META;
    if (m_is_creator) {
        // The creator is not freeing chunks. (If there are no consumers, the write buffer is returned as the min read buffer, so no need to free.)
        return true;
    }

    size_t read_offset = __sync_fetch_and_add(&meta->consumers[m_consumer_id].read_offset, 0);
    size_t deepest_write = __sync_fetch_and_add(&meta->deepest_write, 0);
    // Wrap around happened after the last buff freed
    if (read_offset == deepest_write) {
        read_offset = 0;
    }

    // Check that the read offset is in the beggining of this buff
    if (offset != read_offset) {
        LOG(FATAL) << "Can't free chunks out of order of allocation. "
                   << "consumer_id=" << std::to_string(m_consumer_id) << " shmkey=" << std::hex << m_shmkey << std::dec
                   << " offset=" << std::to_string(offset) << " read_offset=" << std::to_string(read_offset)
                   << " meta->deepest_write=" << std::to_string(deepest_write);
        return false;
    }

    read_offset += size;

    __sync_add_and_fetch(&meta->consumers[m_consumer_id].read_count, 1);
    __sync_bool_compare_and_swap(&meta->consumers[m_consumer_id].read_offset, meta->consumers[m_consumer_id].read_offset,
                                 read_offset);
    LOG(DEBUG) << "Freed buff. consumer_id=" << std::to_string(m_consumer_id) << " shmkey=" << std::hex << m_shmkey << std::dec
               << " new read_offset=" << std::to_string(meta->consumers[m_consumer_id].read_offset)
               << " meta->deepest_write=" << std::to_string(deepest_write)
               << " read_count=" << meta->consumers[m_consumer_id].read_count;

    return true;
}

bool shmem_base::remove_consumer(int8_t consumer_id)
{
    if (m_is_initialized == false) {
        LOG(ERROR) << "cant remove consumer, not initialized";
        return false;
    }

    shmem_meta *meta = GET_META;
    lock_raii lock(&meta->lock);

    meta->consumers[consumer_id].read_count = meta->write_count;
    meta->consumers[consumer_id].read_offset = meta->write_offset;

    // remove consumer_id from the list it is in:
    int8_t next = meta->consumers[consumer_id].next_consumer;
    int8_t prev = meta->consumers[consumer_id].prev_consumer;
    if (-1 != next) {
        meta->consumers[next].prev_consumer = prev;
    }
    if (-1 != prev) {
        meta->consumers[prev].next_consumer = next;
    }
    if (consumer_id == meta->first_used_consumer) {
        meta->first_used_consumer = next;
    }

    // put consumer_id into list of unused consumers;
    int8_t old_head = meta->first_unused_consumer;
    meta->consumers[consumer_id].next_consumer = old_head;
    if (-1 != old_head) {
        meta->consumers[old_head].prev_consumer = consumer_id;
    }
    meta->consumers[consumer_id].prev_consumer = -1;
    meta->first_unused_consumer = consumer_id;

    meta->number_of_consumers--;
    return true;
}

// this function gets the 'minimum' read offset - the one that needs to read the most.
// if no consumer is attached, the write offset is returned.
size_t shmem_base::get_min_read_offset()
{
    shmem_meta *meta = GET_META;
    lock_raii lock(&meta->lock);
    size_t write_offset = __sync_fetch_and_add(&meta->write_offset, 0);

    size_t min_read_offset = write_offset;
    size_t shift =
        m_block_size +
        1; // shift everything before write count by something that's greater than block_size so that it would be sorted correctly
    min_read_offset += shift;

    int8_t consumer_id = __sync_fetch_and_add(&meta->first_used_consumer, 0);

    while (-1 != consumer_id) {
        size_t read_offset = __sync_fetch_and_add(&meta->consumers[consumer_id].read_offset, 0);
        // In case we had wrap around - there are readers with pointer less then others.
        if ((read_offset < write_offset) ||
            (read_offset == write_offset && meta->consumers[consumer_id].read_count == meta->write_count)) {
            read_offset += shift;
        }
        min_read_offset = std::min(read_offset, min_read_offset);
        consumer_id = __sync_fetch_and_add(&meta->consumers[consumer_id].next_consumer, 0);
    }

    if (min_read_offset > m_block_size) {
        min_read_offset -= shift;
    }

    return min_read_offset;
}

size_t shmem_base::get_total_read_count()
{
    size_t total_read_count = 0;
    shmem_meta *meta = GET_META;
    lock_raii lock(&meta->lock);
    if (meta->number_of_consumers == 0) {
        return meta->write_count;
    }

    int8_t consumer_id = __sync_fetch_and_add(&meta->first_used_consumer, 0);

    while (-1 != consumer_id) {
        total_read_count += __sync_fetch_and_add(&meta->consumers[consumer_id].read_count, 0);
        consumer_id = __sync_fetch_and_add(&meta->consumers[consumer_id].next_consumer, 0);
    }
    return total_read_count;
}

size_t shmem_base::calc_write_count()
{
    shmem_meta *meta = GET_META;
    if (meta->number_of_consumers == 0)
        return meta->write_count;

    return meta->write_count * meta->number_of_consumers;
}

size_t shmem_base::write_count()
{
    shmem_meta *meta = GET_META;
    return meta->write_count - 1;
}

size_t shmem_base::wrap_count()
{
    shmem_meta *meta = GET_META;
    return meta->wrap_count;
}

bool shmem_base::is_valid(size_t offset, size_t write_count, size_t wrap_count)
{
    if (m_is_synced) {
        return true;
    }

    shmem_meta *meta = GET_META;
    lock_raii lock(&meta->lock);

    uint64_t current_wrap_count = __sync_fetch_and_add(&meta->wrap_count, 0);
    uint64_t current_write_offset = __sync_fetch_and_add(&meta->write_offset, 0);

    if ((current_wrap_count > wrap_count + 1) || ((current_wrap_count == wrap_count + 1) && (offset < current_write_offset))) {
        LOG(DEBUG) << " Tried to get invalid buffer. consumer_id=" << std::to_string(m_consumer_id) << " shmkey=" << std::hex
                   << m_shmkey << std::dec << " offset=" << std::to_string(offset) << " write_count=" << std::to_string(write_count)
                   << " wrap_count=" << std::to_string(wrap_count) << " current_wrap_count=" << std::to_string(current_wrap_count)
                   << " current_write_offset=" << std::to_string(current_write_offset);
        return false;
    }

    meta->consumers[m_consumer_id].read_offset = offset;
    meta->consumers[m_consumer_id].read_count = write_count;
    m_is_synced = true;

    LOG(INFO) << "Synced! consumer_id=" << std::to_string(m_consumer_id) << " shmkey=" << std::hex << m_shmkey << std::dec
              << " read_offset=" << std::to_string(meta->consumers[m_consumer_id].read_offset)
              << " read_count=" << std::to_string(meta->consumers[m_consumer_id].read_count);
    return true;
}

shmem_buff::shmem_buff(std::shared_ptr<imif::common::shmem_pool> pool, const messages::memory::ShmemBuff &buff) : m_pool(pool.get())
{
    init(buff);
}

shmem_buff::shmem_buff(shmem_pool *pool, uint8_t *ptr) : m_pool(pool), m_ptr(ptr) {}

shmem_buff::~shmem_buff() { free(); }

bool shmem_buff::reallocate(size_t new_size)
{
    if (m_freed) {
        LOG(ERROR) << "Can't resize freed buff";
        return false;
    }
    if (!m_pool) {
        LOG(FATAL) << "shmem_buff without a valid block";
        return false;
    }

    if (!m_pool->realloc_buff(this, new_size)) {
        LOG(ERROR) << "Failed reallocate buff!";
        return false;
    }

    m_ptr = m_pool->ptr() + offset();

    return true;
}

bool shmem_buff::resize(size_t delta)
{
    if (m_freed) {
        LOG(ERROR) << "Can't resize freed buff";
        return false;
    }
    if (!m_pool) {
        LOG(FATAL) << "shmem_buff without a valid block";
        return false;
    }

    return m_pool->resize_buff(this, delta);
}

bool shmem_buff::free()
{
    if (m_freed) {
        return true;
    }

    if (!m_valid) {
        return true;
    }

    if (!m_pool) {
        LOG(FATAL) << "shmem_buff without a valid block";
        return false;
    }

    if (!m_pool->free_buff(offset(), buff_size())) {
        return false;
    }

    m_freed = true;
    return true;
}

messages::memory::ShmemBuff shmem_buff::split(size_t split)
{
    messages::memory::ShmemBuff buff;
    if (!m_pool) {
        LOG(FATAL) << "shmem_buff without a valid block";
        return buff;
    }

    m_pool->split_buff();

    buff.CopyFrom(*this);
    buff.set_buff_size(split);

    set_offset(offset() + split);
    set_buff_size(buff_size() - split);

    return buff;
}

bool shmem_buff::drop()
{
    if (m_freed) {
        LOG(ERROR) << "Can't drop freed buffer!";
        return false;
    }
    if (!m_pool) {
        LOG(FATAL) << "shmem_buff without a valid block";
        return false;
    }

    if (!m_pool->drop_buff(this)) {
        return false;
    }

    m_freed = true;
    return true;
}

bool shmem_buff::init(const messages::memory::ShmemBuff &buff)
{
    CopyFrom(buff);

    if (!m_pool) {
        LOG(ERROR) << "Failed getting block for shmkey=" << shmkey();
        return false;
    }

    m_ptr = m_pool->ptr() + offset();

    m_valid = m_pool->is_valid(offset(), write_count(), wrap_count());

    return true;
}

shmem_pool::shmem_pool(int shmkey, size_t size, bool producer) : shmem_base(shmkey, size, producer) {}

bool shmem_pool::is_valid(size_t offset, size_t write_count, size_t wrap_count)
{
    return shmem_base::is_valid(offset, write_count, wrap_count);
}

std::shared_ptr<shmem_buff> shmem_pool::alloc_buff(size_t size)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't allocate buff from non creator pool";
        return nullptr;
    }

    size_t offset = 0;
    if (!alloc(size, &offset)) {
        // LOG(ERROR) << "Failed allocating buff!";
        return nullptr;
    }

    auto buff = std::make_shared<shmem_buff>(this, m_ptr + offset);
    buff->set_shmkey(m_shmkey);
    buff->set_shmsize(m_block_size);
    buff->set_buff_size(size);
    buff->set_offset(offset);
    buff->set_write_count(write_count());
    buff->set_wrap_count(wrap_count());

    return buff;
}

bool shmem_pool::resize_buff(shmem_buff *buff, size_t delta)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't resize buff from non creator pool";
        return false;
    }

    if (buff->shmkey() != uint32_t(m_shmkey)) {
        LOG(ERROR) << "The buff is not allocated from this block!";
        return false;
    }

    if (!resize(buff->offset(), buff->buff_size(), delta)) {
        LOG(ERROR) << "Can't resize the buff at offset=" << buff->offset();
        return false;
    }

    buff->set_buff_size(buff->buff_size() + delta);

    return true;
}

bool shmem_pool::resize_buff(std::shared_ptr<shmem_buff> buff, size_t delta) { return resize_buff(buff.get(), delta); }

bool shmem_pool::realloc_buff(shmem_buff *buff, size_t new_size)
{
    if (!m_is_creator) {
        LOG(ERROR) << "Can't resize buff from non creator pool";
        return false;
    }

    if (buff->shmkey() != uint32_t(m_shmkey)) {
        LOG(ERROR) << "The buff is not allocated from this block!";
        return false;
    }

    size_t offset = buff->offset();
    if (!reallocate(buff->buff_size(), new_size, &offset)) {
        // LOG(ERROR) << "Failed allocating buff!";
        return false;
    }

    if (offset != buff->offset()) {
        // Copy the memory
        std::memmove(ptr() + offset, ptr() + buff->offset(), buff->buff_size());

        // decrement the write count by 1 since we allocated a new buffer. the old one should be dropped....
        dec_write();
    }

    buff->set_buff_size(new_size);
    buff->set_offset(offset);

    return true;
}

bool shmem_pool::realloc_buff(std::shared_ptr<shmem_buff> buff, size_t new_size) { return realloc_buff(buff.get(), new_size); }

bool shmem_pool::free_buff(std::shared_ptr<shmem_buff> buff)
{
    if (!buff) {
        LOG(ERROR) << "buff is null!";
        return false;
    }
    if (buff->freed()) {
        LOG(ERROR) << "Can't free already freed buffer";
        return false;
    }
    if (!free(buff->offset(), buff->buff_size())) {
        LOG(ERROR) << "Failed freeing buff!";
        return false;
    }

    buff->freed(true);

    return true;
}

bool shmem_pool::free_buff(size_t offset, size_t size)
{
    if (!free(offset, size)) {
        LOG(ERROR) << "Failed freeing buff!";
        return false;
    }

    return true;
}

bool shmem_pool::drop_buff(shmem_buff *buff)
{
    if (!buff) {
        LOG(ERROR) << "buff is null!";
        return false;
    }

    if (buff->freed()) {
        LOG(ERROR) << "Can't drop already freed buffer";
        return false;
    }
    if (!drop(buff->offset(), buff->buff_size())) {
        LOG(ERROR) << "Failed freeing buff!";
        return false;
    }

    buff->freed(true);
    return true;
}

bool shmem_pool::drop_buff(std::shared_ptr<shmem_buff> buff) { return drop_buff(buff.get()); }

bool shmem_pool::split_buff() { return inc_write(); }

thread_local std::unordered_map<int, std::shared_ptr<shmem_pool>> shmem_buff_factory::shmem_pool_map =
    std::unordered_map<int, std::shared_ptr<shmem_pool>>();

std::shared_ptr<shmem_pool> shmem_buff_factory::get_shmem_pool(int shmkey, size_t shmsize)
{
    auto element = shmem_pool_map.find(shmkey);
    if (element != shmem_pool_map.end()) {
        return element->second;
    }

    auto block = std::make_shared<shmem_pool>(shmkey, shmsize, false);
    if (!block->attach()) {
        LOG(ERROR) << "Failed attaching to shmem";
        return nullptr;
    }
    shmem_pool_map[shmkey] = block;
    return block;
}

bool shmem_buff_factory::free_shmem_pool(uint32_t shmkey)
{
    auto element = shmem_pool_map.find(shmkey);
    if (element == shmem_pool_map.end()) {
        LOG(ERROR) << "Can't free shmkey " << std::hex << shmkey << std::dec << ". wasn't found!";
        return false;
    }

    shmem_pool_map.erase(element);
    return true;
}

std::shared_ptr<shmem_buff> shmem_buff_factory::get_buff(uint8_t *buf, int size)
{
    messages::memory::ShmemBuff buff;
    if (!buff.ParseFromArray(buf, size)) {
        LOG(ERROR) << "Failed parsing buff!";
        return nullptr;
    }

    return get_buff(buff);
}

std::shared_ptr<shmem_buff> shmem_buff_factory::get_buff(const messages::memory::ShmemBuff &buff)
{
    auto pool = get_shmem_pool(buff.shmkey(), buff.shmsize());
    if (!pool) {
        LOG(ERROR) << "Can't get shm_pool for key=" << std::to_string(buff.shmkey());
        return nullptr;
    }

    return std::make_shared<shmem_buff>(pool, buff);
}

} // namespace common
} // namespace imif
