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

#include "avcall_meta_data.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVCallMetaData::Marshalling(Parcel& parcel) const
{
    return parcel.WriteString(callMetaMask_.to_string()) &&
        parcel.WriteString(name_) &&
        parcel.WriteString(phoneNumber_) &&
        parcel.WriteString(mediaImageUri_) &&
        parcel.WriteParcelable(mediaImage_.get());
}

AVCallMetaData *AVCallMetaData::Unmarshalling(Parcel& data)
{
    std::string mask;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(mask) && mask.length() == AVCALL_META_KEY_MAX, nullptr, "mask not valid");
    CHECK_AND_RETURN_RET_LOG(mask.find_first_not_of("01") == std::string::npos, nullptr, "mask string not 0 or 1");

    auto *result = new (std::nothrow) AVCallMetaData();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVCallMetaData failed");
    result->callMetaMask_ = AVCallMetaMaskType(mask);
    if (!data.ReadString(result->name_) ||
        !data.ReadString(result->phoneNumber_) ||
        !data.ReadString(result->mediaImageUri_)) {
        SLOGE("read AVCallMetaData failed");
        delete result;
        return nullptr;
    }
    result->mediaImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->callMetaMask_.test(AVCALL_META_KEY_MEDIA_IMAGE) && result->mediaImage_ == nullptr) {
        SLOGE("read PixelMap failed");
        delete result;
        return nullptr;
    }
    return result;
}

void AVCallMetaData::SetName(const std::string& name)
{
    name_ = name;
    callMetaMask_.set(AVCALL_META_KEY_NAME);
}

std::string AVCallMetaData::GetName() const
{
    return name_;
}

void AVCallMetaData::SetPhoneNumber(const std::string& phoneNumber)
{
    phoneNumber_ = phoneNumber;
    callMetaMask_.set(AVCALL_META_KEY_PHONE_NUMBER);
}

std::string AVCallMetaData::GetPhoneNumber() const
{
    return phoneNumber_;
}

void AVCallMetaData::SetMediaImage(const std::shared_ptr<AVSessionPixelMap>& mediaImage)
{
    mediaImage_ = mediaImage;
    callMetaMask_.set(AVCALL_META_KEY_MEDIA_IMAGE);
}

std::shared_ptr<AVSessionPixelMap> AVCallMetaData::GetMediaImage() const
{
    return mediaImage_;
}

void AVCallMetaData::SetMediaImageUri(const std::string& mediaImageUri)
{
    mediaImageUri_ = mediaImageUri;
    callMetaMask_.set(AVCALL_META_KEY_MEDIA_IMAGE_URI);
}

std::string AVCallMetaData::GetMediaImageUri() const
{
    return mediaImageUri_;
}

AVCallMetaData::AVCallMetaMaskType AVCallMetaData::GetAVCallMetaMask() const
{
    return callMetaMask_;
}

void AVCallMetaData::Reset()
{
    callMetaMask_.reset();
    name_ = "";
    phoneNumber_ = "";
    mediaImageUri_ = "";
    mediaImage_ = nullptr;
}

bool AVCallMetaData::CopyToByMask(AVCallMetaMaskType& mask, AVCallMetaData& metaOut) const
{
    bool result = false;
    auto intersection = callMetaMask_ & mask;
    for (int i = 0; i < AVCALL_META_KEY_MAX; i++) {
        if (intersection.test(i)) {
            cloneActions[i](*this, metaOut);
            metaOut.callMetaMask_.set(i);
            result = true;
        }
    }

    return result;
}

bool AVCallMetaData::CopyFrom(const AVCallMetaData& metaIn)
{
    if (metaIn.name_.empty()) {
        SLOGE("assetId is empty");
        return false;
    }

    if (metaIn.name_ != name_) {
        SLOGD("name_ not equal");
        *this = metaIn;
        return true;
    }

    bool result = false;
    for (int i = 0; i < AVCALL_META_KEY_MAX; i++) {
        if (metaIn.callMetaMask_.test(i)) {
            cloneActions[i](metaIn, *this);
            callMetaMask_.set(i);
            result = true;
        }
    }

    return result;
}

bool AVCallMetaData::IsValid() const
{
    return phoneNumber_ != "";
}

void AVCallMetaData::CloneName(const AVCallMetaData& from, AVCallMetaData& to)
{
    to.name_ = from.name_;
}

void AVCallMetaData::ClonePhoneNumber(const AVCallMetaData& from, AVCallMetaData& to)
{
    to.phoneNumber_ = from.phoneNumber_;
}

void AVCallMetaData::CloneMediaImage(const AVCallMetaData& from, AVCallMetaData& to)
{
    to.mediaImage_ = from.mediaImage_;
}

void AVCallMetaData::CloneMediaImageUri(const AVCallMetaData& from, AVCallMetaData& to)
{
    to.mediaImageUri_ = from.mediaImageUri_;
}
} // namespace OHOS::AVSession
