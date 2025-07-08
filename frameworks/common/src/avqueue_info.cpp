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

#include "avqueue_info.h"
#include "avsession_log.h"
#include "securec.h"

namespace OHOS::AVSession {
bool AVQueueInfo::Marshalling(Parcel& parcel) const
{
    return MarshallingMessageParcel(static_cast<MessageParcel&>(parcel));
}

bool AVQueueInfo::MarshallingMessageParcel(MessageParcel& parcel) const
{
    return parcel.WriteString(bundleName_) &&
        parcel.WriteString(avQueueName_) &&
        parcel.WriteString(avQueueId_) &&
        parcel.WriteString(avQueueImageUri_) &&
        MarshallingQueueImage(parcel);
}

bool AVQueueInfo::MarshallingQueueImage(MessageParcel& parcel) const
{
    int imageLength = 0;
    std::vector<uint8_t> avQueueImageBuffer;
    if (avQueueImage_ != nullptr) {
        avQueueImageBuffer = avQueueImage_->GetInnerImgBuffer();
        imageLength = static_cast<int>(avQueueImageBuffer.size());
    }
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(imageLength), false, "write image length fail");
    CHECK_AND_RETURN_RET_LOG(imageLength > 0, true, "no image");

    unsigned char *buffer = new (std::nothrow) unsigned char[imageLength];
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, false, "new buffer failed");

    memcpy_s(buffer, imageLength, avQueueImageBuffer.data(), imageLength);

    bool ret = parcel.WriteRawData(buffer, imageLength);
    delete[] buffer;
    CHECK_AND_RETURN_RET_LOG(ret, false, "WriteRawData failed");
    return true;
}

AVQueueInfo* AVQueueInfo::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<AVQueueInfo>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->UnmarshallingMessageParcel(static_cast<MessageParcel&>(in)),
        nullptr, "info is nullptr");
    return info.release();
}

bool AVQueueInfo::UnmarshallingMessageParcel(MessageParcel& data)
{
    bool ret = data.ReadString(bundleName_) &&
        data.ReadString(avQueueName_) &&
        data.ReadString(avQueueId_) &&
        data.ReadString(avQueueImageUri_);
    CHECK_AND_RETURN_RET_LOG(ret, false, "read data failed");

    int32_t imageLength {};
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(imageLength), false, "read image length failed");
    CHECK_AND_RETURN_RET_LOG(imageLength > 0, true, "no image");

    const char *buffer = nullptr;
    buffer = reinterpret_cast<const char *>(data.ReadRawData(imageLength));
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, false, "read raw data null buffer");

    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> mediaImageBuffer(buffer, buffer + imageLength);
    avQueuePixelMap->SetInnerImgBuffer(mediaImageBuffer);
    avQueueImage_ = avQueuePixelMap;
    return true;
}

void AVQueueInfo::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
}

std::string AVQueueInfo::GetBundleName() const
{
    return bundleName_;
}

void AVQueueInfo::SetAVQueueName(const std::string& avQueueName)
{
    avQueueName_ = avQueueName;
}

std::string AVQueueInfo::GetAVQueueName() const
{
    return avQueueName_;
}

void AVQueueInfo::SetAVQueueId(const std::string& avQueueId)
{
    avQueueId_ = avQueueId;
}

std::string AVQueueInfo::GetAVQueueId() const
{
    return avQueueId_;
}

void AVQueueInfo::SetAVQueueImage(const std::shared_ptr<AVSessionPixelMap>& avQueueImage)
{
    avQueueImage_ = avQueueImage;
}

std::shared_ptr<AVSessionPixelMap> AVQueueInfo::GetAVQueueImage() const
{
    return avQueueImage_;
}

void AVQueueInfo::SetAVQueueLength(const int32_t avQueueLength)
{
    avQueueLength_ = avQueueLength;
}

int32_t AVQueueInfo::GetAVQueueLength() const
{
    return avQueueLength_;
}

void AVQueueInfo::SetAVQueueImageUri(const std::string& avQueueImageUri)
{
    avQueueImageUri_ = avQueueImageUri;
}

std::string AVQueueInfo::GetAVQueueImageUri() const
{
    return avQueueImageUri_;
}
} // namespace OHOS::AVSession