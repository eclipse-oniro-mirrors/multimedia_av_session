/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_AVCALL_META_DATA_H
#define OHOS_AVCALL_META_DATA_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avsession_pixel_map.h"

#ifndef WINDOWS_PLATFORM
#ifndef MAC_PLATFORM
#ifndef IOS_PLATFORM
#include <malloc.h>
#endif
#endif
#endif

namespace OHOS::AVSession {
class AVCallMetaData : public Parcelable {
public:
    enum {
        AVCALL_META_KEY_NAME = 0,
        AVCALL_META_KEY_PHONE_NUMBER = 1,
        AVCALL_META_KEY_MEDIA_IMAGE = 2,
        AVCALL_META_KEY_MEDIA_IMAGE_URI = 3,
        AVCALL_META_KEY_MAX = 4
    };

    using AVCallMetaMaskType = std::bitset<AVCALL_META_KEY_MAX>;

    AVCallMetaData() = default;
    ~AVCallMetaData() = default;

    static AVCallMetaData* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetName(const std::string& assetId);
    std::string GetName() const;

    void SetPhoneNumber(const std::string& title);
    std::string GetPhoneNumber() const;

    void SetMediaImage(const std::shared_ptr<AVSessionPixelMap>& mediaImage);
    std::shared_ptr<AVSessionPixelMap> GetMediaImage() const;

    void SetMediaImageUri(const std::string& mediaImageUri);
    std::string GetMediaImageUri() const;

    void Reset();

    AVCallMetaMaskType GetAVCallMetaMask() const;

    bool CopyToByMask(AVCallMetaMaskType& mask, AVCallMetaData& metaOut) const;
    bool CopyFrom(const AVCallMetaData& metaIn);

    bool IsValid() const;

    const static inline std::vector<int32_t> localCapability {
        AVCALL_META_KEY_NAME,
        AVCALL_META_KEY_PHONE_NUMBER,
        AVCALL_META_KEY_MEDIA_IMAGE,
        AVCALL_META_KEY_MEDIA_IMAGE_URI
    };

private:
    AVCallMetaMaskType callMetaMask_;

    std::string name_ = "";
    std::string phoneNumber_ = "";
    std::shared_ptr<AVSessionPixelMap> mediaImage_ = nullptr;
    std::string mediaImageUri_ = "";

    static void CloneName(const AVCallMetaData& from, AVCallMetaData& to);
    static void ClonePhoneNumber(const AVCallMetaData& from, AVCallMetaData& to);
    static void CloneMediaImage(const AVCallMetaData& from, AVCallMetaData& to);
    static void CloneMediaImageUri(const AVCallMetaData& from, AVCallMetaData& to);

    using CloneActionType = void(*)(const AVCallMetaData& from, AVCallMetaData& to);
    static inline CloneActionType cloneActions[AVCALL_META_KEY_MAX] = {
        &AVCallMetaData::CloneName,
        &AVCallMetaData::ClonePhoneNumber,
        &AVCallMetaData::CloneMediaImage,
        &AVCallMetaData::CloneMediaImageUri
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCALL_META_DATA_H
