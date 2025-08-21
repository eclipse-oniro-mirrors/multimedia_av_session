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
    return parcel.WriteString(bundleName_) &&
        parcel.WriteString(avQueueName_) &&
        parcel.WriteString(avQueueId_) &&
        parcel.WriteString(avQueueImageUri_) &&
        parcel.WriteParcelable(avQueueImage_.get());
}

bool AVQueueInfo::Unmarshalling(Parcel& data)
{
    CHECK_AND_RETURN_RET_LOG(data.ReadString(bundleName_), false, "read bundleName failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(avQueueName_), false, "read avQueueName failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(avQueueId_), false, "read avQueueId failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(avQueueImageUri_), false, "read avQueueImageUri failed");

    avQueueImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    CHECK_AND_RETURN_RET_LOG(avQueueImage_ != nullptr, false, "read AVQueueInfo PixelMap failed");
    return true;
}

bool AVQueueInfo::MarshallingMessageParcel(MessageParcel& parcel) const
{
    return parcel.WriteString(bundleName_) &&
        parcel.WriteString(avQueueName_) &&
        parcel.WriteString(avQueueId_) &&
        parcel.WriteString(avQueueImageUri_) &&
        MarshallingQueueImage(parcel);
}

AVQueueInfo* AVQueueInfo::UnmarshallingMessageParcel(MessageParcel& data)
{
    auto *result = new (std::nothrow) AVQueueInfo();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVQueueInfo failed");

    bool ret = data.ReadString(result->bundleName_) && data.ReadString(result->avQueueName_) &&
        data.ReadString(result->avQueueId_) && data.ReadString(result->avQueueImageUri_);
    if (!ret) {
        SLOGE("read AVQueueInfo failed");
        delete result;
        return nullptr;
    }

    int imageLength = data.ReadInt32();
    int32_t maxImageSize = 10 * 1024 *1024;
    CHECK_AND_RETURN_RET_LOG(imageLength > 0 && imageLength <= maxImageSize, result,
        "AVQueueInfo::UnmarshallingMessageParcel image length 0 or exceed max image size");
    const char *buffer = nullptr;
    buffer = reinterpret_cast<const char *>(data.ReadRawData(imageLength));
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, result, "read raw data null buffer");

    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> mediaImageBuffer(buffer, buffer + imageLength);
    avQueuePixelMap->SetInnerImgBuffer(mediaImageBuffer);
    result->avQueueImage_ = avQueuePixelMap;
    return result;
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