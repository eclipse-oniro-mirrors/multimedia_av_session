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

namespace OHOS::AVSession {
constexpr size_t DEFAULT_BUFFER_SIZE = 160 * 1024;
class AVSessionPixelMap : public Parcelable {
public:
    AVSessionPixelMap() = default;
    ~AVSessionPixelMap() = default;

    bool Marshalling(Parcel &data) const override;
    static AVSessionPixelMap *Unmarshalling(Parcel &data);

    std::vector<uint8_t> GetPixelData() const
    {
        return data_;
    }

    void SetPixelData(const std::vector<uint8_t> &data)
    {
        data_.clear();
        data_ = data;
    }

    std::vector<uint8_t> GetImageInfo() const
    {
        return imageInfo_;
    }

    void SetImageInfo(const std::vector<uint8_t> &imageInfo)
    {
        imageInfo_.clear();
        imageInfo_ = imageInfo;
    }

private:
    std::vector<uint8_t> data_ = std::vector<uint8_t>(DEFAULT_BUFFER_SIZE);
    std::vector<uint8_t> imageInfo_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_PIXEL_MAP_H