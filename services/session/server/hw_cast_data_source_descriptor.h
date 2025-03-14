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

#ifndef HW_CAST_DATA_SOURCE_DESCRIPTOR_H
#define HW_CAST_DATA_SOURCE_DESCRIPTOR_H

#include "cast_data_source.h"

namespace OHOS {
namespace AVSession {

class HwCastDataSourceDescriptor : public CastEngine::ICastDataSource {
public:
    virtual ~HwCastDataSourceDescriptor();
    int32_t ReadAt(const std::shared_ptr<CastEngine::CastSharedMemory> &mem, uint32_t length,
        int64_t pos = -1) override;
    int32_t GetSize(int64_t &size) override;
    void SetCallback(std::function<int32_t(void*, uint32_t, int64_t)> callback);
    void SetSize(int64_t size);

private:
    std::function<int32_t(void*, uint32_t, int64_t)> callback_ = nullptr;
    int64_t size_ = 0;
};
} // namespace AVSession
} // namespace OHOS
#endif // HW_CAST_DATA_SOURCE_DESCRIPTOR_H