/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hw_cast_data_source_descriptor.h"
#include "avsession_log.h"

namespace OHOS {
namespace AVSession {

HwCastDataSourceDescriptor::~HwCastDataSourceDescriptor()
{
    SLOGI("destructor in");
}

int32_t HwCastDataSourceDescriptor::ReadAt(const std::shared_ptr<CastEngine::CastSharedMemory> &mem,
    uint32_t length, int64_t pos)
{
    int32_t result = 0;
    int32_t memorySize = mem->GetSize();
    SLOGI("ReadAt size is = %{public}d length is %{public}d", memorySize, length);
    if (callback_ != nullptr) {
        result = callback_(mem.get(), length, pos);
    } else {
        SLOGE("no callback");
    }
    SLOGI("after read %{public}s", mem->GetBase());
    return result;
}

int32_t HwCastDataSourceDescriptor::GetSize(int64_t &size)
{
    SLOGE("GetSize in");
    size = size_;
    return 0;
}

void HwCastDataSourceDescriptor::SetCallback(std::function<int32_t(void*, uint32_t, int64_t)> callback)
{
    callback_ = callback;
}

void HwCastDataSourceDescriptor::SetSize(int64_t size)
{
    size_ = size;
}

} // namespace AVSession
} // namespace OHOS