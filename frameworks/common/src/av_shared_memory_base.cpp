/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 */


#include <sys/mman.h>
#include <unistd.h>
#include "ashmem.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "securec.h"
#include "av_shared_memory_base.h"

namespace {
static std::atomic<uint64_t> g_uniqueSharedMemoryID = 0;
}

namespace OHOS {
namespace AVSession {
struct AVSharedMemoryBaseImpl : public AVSharedMemoryBase {
public:
    AVSharedMemoryBaseImpl(int32_t fd, int32_t size, uint32_t flags, const std::string &name)
        : AVSharedMemoryBase(fd, size, flags, name) {}
};

std::shared_ptr<AVSharedMemory> AVSharedMemoryBase::CreateFromLocal(
    int32_t size, uint32_t flags, const std::string &name)
{
    std::shared_ptr<AVSharedMemoryBase> memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    int32_t ret = memory->Init();
    if (ret != static_cast<int32_t>(AVSESSION_SUCCESS)) {
        SLOGE("Create avsharedmemory failed, ret = %{public}d", ret);
        return nullptr;
    }

    return memory;
}

std::shared_ptr<AVSharedMemory> AVSharedMemoryBase::CreateFromRemote(
    int32_t fd, int32_t size, uint32_t flags, const std::string &name)
{
    std::shared_ptr<AVSharedMemoryBase> memory = std::make_shared<AVSharedMemoryBaseImpl>(fd, size, flags, name);
    int32_t ret = memory->Init();
    if (ret != static_cast<int32_t>(AVSESSION_SUCCESS)) {
        SLOGE("Create avsharedmemory failed, ret = %{public}d", ret);
        return nullptr;
    }

    return memory;
}

AVSharedMemoryBase::AVSharedMemoryBase(int32_t size, uint32_t flags, const std::string &name)
    : base_(nullptr), capacity_(size), flags_(flags), name_(name), fd_(-1), size_(0)
{
    SLOGD("AVSharedMemoryBase size in name = %{public}s", name_.c_str());
    uniqueSharedMemoryID_ = g_uniqueSharedMemoryID++;
}

AVSharedMemoryBase::AVSharedMemoryBase(int32_t fd, int32_t size, uint32_t flags, const std::string &name)
    : base_(nullptr), capacity_(size), flags_(flags), name_(name), fd_(dup(fd)), size_(0)
{
    SLOGD("AVSharedMemoryBase fd in, name = %{public}s", name_.c_str());
    uniqueSharedMemoryID_ = g_uniqueSharedMemoryID++;
}

AVSharedMemoryBase::~AVSharedMemoryBase()
{
    SLOGD("~AVSharedMemoryBase, name = %{public}s", name_.c_str());
    Close();
}

int32_t AVSharedMemoryBase::Init(bool isMapVirAddr)
{
    if (capacity_ <= 0) {
        SLOGE("size is invalid, size = %{public}d", capacity_);
        return static_cast<int32_t>(ERR_INVALID_PARAM);
    }

    bool isRemote = false;
    if (fd_ > 0) {
        int size = AshmemGetSize(fd_);
        if (size != capacity_) {
            SLOGE("size not equal capacity_, size = %{public}d, capacity_ = %{public}d", size, capacity_);
            return static_cast<int32_t>(ERR_INVALID_PARAM);
        }
        isRemote = true;
    } else {
        fd_ = AshmemCreate(name_.c_str(), static_cast<size_t>(capacity_));
        if (fd_ <= 0) {
            SLOGE("fd is invalid, fd = %{public}d", fd_);
            return static_cast<int32_t>(ERR_INVALID_PARAM);
        }
    }
    if (isMapVirAddr) {
        int32_t ret = MapMemory(isRemote);
        if (ret != static_cast<int32_t>(AVSESSION_SUCCESS)) {
            SLOGE("MapMemory failed, ret = %{public}d", ret);
            return static_cast<int32_t>(ERR_INVALID_PARAM);
        }
    }
    return static_cast<int32_t>(AVSESSION_SUCCESS);
}

int32_t AVSharedMemoryBase::MapMemory(bool isRemote)
{
    unsigned int prot = PROT_READ | PROT_WRITE;
    if (isRemote && (flags_ & FLAGS_READ_ONLY)) {
        prot &= ~PROT_WRITE;
    }

    int result = AshmemSetProt(fd_, static_cast<int>(prot));
    if (result < 0) {
        SLOGE("AshmemSetProt failed, result = %{public}d", result);
        return static_cast<int32_t>(AVSESSION_ERROR);
    }

    void *addr = ::mmap(nullptr, static_cast<size_t>(capacity_), static_cast<int>(prot), MAP_SHARED, fd_, 0);
    if (addr == MAP_FAILED) {
        SLOGE("mmap failed, please check params");
        return static_cast<int32_t>(AVSESSION_ERROR);
    }

    base_ = reinterpret_cast<uint8_t*>(addr);
    return static_cast<int32_t>(AVSESSION_SUCCESS);
}

void AVSharedMemoryBase::Close() noexcept
{
    if (base_ != nullptr) {
        (void)::munmap(base_, static_cast<size_t>(capacity_));
        base_ = nullptr;
        capacity_ = 0;
        flags_ = 0;
        size_ = 0;
    }
    if (fd_ > 0) {
        (void)::close(fd_);
        fd_ = -1;
    }
}

int32_t AVSharedMemoryBase::Write(const uint8_t *in, int32_t writeSize, int32_t position)
{
    if (in == nullptr) {
        SLOGE("Input buffer is nullptr");
        return 0;
    }
    if (writeSize <= 0) {
        SLOGE("Input writeSize:%{public}d is invalid", writeSize);
        return 0;
    }
    int32_t start = 0;
    if (position == INVALID_POSITION) {
        start = size_;
    } else {
        start = std::min(position, capacity_);
    }
    int32_t unusedSize = capacity_ - start;
    int32_t length = std::min(writeSize, unusedSize);
    SLOGD("write data,length:%{public}d, start:%{public}d, name:%{public}s", length, start, name_.c_str());
    if ((length + start) > capacity_) {
        SLOGE("Write out of bounds, length:%{public}d, "
            "start:%{public}d, capacity_:%{public}d", length, start, capacity_);
        return 0;
    }
    uint8_t *dstPtr = base_ + start;
    if (dstPtr == nullptr) {
        SLOGE("Inner dstPtr is nullptr");
        return 0;
    }
    auto error = memcpy_s(dstPtr, length, in, length);
    if (error != EOK) {
        SLOGE("Inner memcpy_s failed,name:%{public}s, %{public}s", name_.c_str(), strerror(error));
        return 0;
    }
    size_ = start + length;
    return length;
}

int32_t AVSharedMemoryBase::Read(uint8_t *out, int32_t readSize, int32_t position)
{
    if (out == nullptr) {
        SLOGE("Input buffer is nullptr");
        return 0;
    }
    if (readSize <= 0) {
        SLOGE("Input readSize:%{public}d is invalid", readSize);
        return 0;
    }
    int32_t start = 0;
    int32_t maxLength = size_;
    if (position != INVALID_POSITION) {
        start = std::min(position, size_);
        maxLength = size_ - start;
    }
    int32_t length = std::min(readSize, maxLength);
    if ((length + start) > capacity_) {
        SLOGE("Read out of bounds, length:%{public}d, "
            "start:%{public}d, capacity_:%{public}d", length, start, capacity_);
        return 0;
    }
    uint8_t *srcPtr = base_ + start;
    if (srcPtr == nullptr) {
        SLOGE("Inner srcPtr is nullptr");
        return 0;
    }
    auto error = memcpy_s(out, length, srcPtr, length);
    if (error != EOK) {
        SLOGE("Inner memcpy_s failed,name:%{public}s, %{public}s", name_.c_str(), strerror(error));
        return 0;
    }
    return length;
}

void AVSharedMemoryBase::ClearUsedSize()
{
    size_ = 0;
}

int32_t AVSharedMemoryBase::GetUsedSize() const
{
    return size_;
}
} // namespace AVSession
} // namespace OHOS