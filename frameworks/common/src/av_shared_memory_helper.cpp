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

#include <unistd.h>
#include "av_shared_memory_helper.h"
#include "av_shared_memory_base.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS {
namespace AVSession {
int32_t WriteAVSharedMemoryToParcel(const std::shared_ptr<AVSharedMemory> &memory, MessageParcel &parcel)
{
    std::shared_ptr<AVSharedMemoryBase> baseMem = std::static_pointer_cast<AVSharedMemoryBase>(memory);
    if (baseMem == nullptr) {
        SLOGE("memory is nullptr");
        return AVSESSION_ERROR;
    }

    int32_t fd = baseMem->GetFd();
    if (fd < 0) {
        SLOGE("write fd is invalid, fd = %{public}d", fd);
        return AVSESSION_ERROR;
    }

    int32_t size = baseMem->GetSize();

    bool res = parcel.WriteFileDescriptor(fd);
    if (!res) {
        SLOGE("write fd is invalid, fd = %{public}d", fd);
        return AVSESSION_ERROR;
    }
    parcel.WriteInt32(size);
    parcel.WriteUint32(baseMem->GetFlags());
    parcel.WriteString(baseMem->GetName());

    return AVSESSION_SUCCESS;
}

std::shared_ptr<AVSharedMemory> ReadAVSharedMemoryFromParcel(MessageParcel &parcel)
{
    int32_t fd  = parcel.ReadFileDescriptor();
    if (fd < 0) {
        SLOGE("read fd is invalid, fd = %{public}d", fd);
        return nullptr;
    }

    int32_t size = parcel.ReadInt32();
    uint32_t flags = parcel.ReadUint32();
    std::string name = parcel.ReadString();

    std::shared_ptr<AVSharedMemory> memory = AVSharedMemoryBase::CreateFromRemote(fd, size, flags, name);
    if (memory == nullptr || memory->GetBase() == nullptr) {
        SLOGE("create remote AVSharedMemoryBase failed");
        return nullptr;
    }

    (void)::close(fd);
    return memory;
}

std::shared_ptr<AVSharedMemory> ReadAVDataSrcMemoryFromParcel(MessageParcel &parcel)
{
    int32_t fd  = parcel.ReadFileDescriptor();
    if (fd < 0) {
        SLOGE("read fd is invalid, fd = %{public}d", fd);
        return nullptr;
    }

    int32_t size = parcel.ReadInt32();
    uint32_t flags = parcel.ReadUint32();
    std::string name = parcel.ReadString();

    std::shared_ptr<AVSharedMemory> memory = AVSharedMemoryBase::CreateFromRemote(fd, size, flags, name);
    if (memory == nullptr || memory->GetBase() == nullptr) {
        SLOGE("create remote AVDataSrcMemory failed");
        return nullptr;
    }

    (void)::close(fd);
    return memory;
}
} // namespace AVSession
} // namespace OHOS