/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_AVSESSION_PIXEL_MAP_H
#define OHOS_AVSESSION_PIXEL_MAP_H

#include <vector>
#include "parcel.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
constexpr size_t DEFAULT_BUFFER_SIZE = 160 * 1024;
class AVSessionPixelMap : public Parcelable {
public:
    AVSessionPixelMap() = default;
    ~AVSessionPixelMap() override
    {
        Clear();
    }

    bool Marshalling(Parcel& parcel) const override;
    static AVSessionPixelMap* Unmarshalling(Parcel& data);

    void Clear()
    {
        innerImgBuffer_.clear();
        std::vector<uint8_t>().swap(innerImgBuffer_);
    }

    std::vector<uint8_t> GetInnerImgBuffer() const
    {
        return innerImgBuffer_;
    }

    void SetInnerImgBuffer(const std::vector<uint8_t>& imgBuffer)
    {
        innerImgBuffer_.clear();
        innerImgBuffer_ = imgBuffer;
        if (innerImgBuffer_.capacity() < DEFAULT_BUFFER_SIZE) {
            innerImgBuffer_.reserve(DEFAULT_BUFFER_SIZE);
        }
    }

private:
    std::vector<uint8_t> innerImgBuffer_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_PIXEL_MAP_H