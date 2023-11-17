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
    if (!data.ReadString(bundleName_) ||
        !data.ReadString(avQueueName_) ||
        !data.ReadString(avQueueId_) ||
        !data.ReadString(avQueueImageUri_)) {
        SLOGE("read AVQueueInfo failed");
        return nullptr;
    }
    avQueueImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (avQueueImage_ == nullptr) {
        SLOGE("read AVQueueInfo PixelMap failed");
        return false;
    }
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

void AVQueueInfo::SetAVQueueImageUri(const std::string& avQueueImageUri)
{
    avQueueImageUri_ = avQueueImageUri;
}

std::string AVQueueInfo::GetAVQueueImageUri() const
{
    return avQueueImageUri_;
}
} // namespace OHOS::AVSession