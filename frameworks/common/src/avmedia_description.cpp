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

#include "avmedia_description.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVMediaDescription::Marshalling(Parcel& parcel) const
{
    return parcel.WriteString(mediaId_) &&
        parcel.WriteString(title_) &&
        parcel.WriteString(subtitle_) &&
        parcel.WriteString(description_) &&
        parcel.WriteString(iconUri_) &&
        parcel.WriteString(mediaUri_) &&
        parcel.WriteParcelable(icon_.get()) &&
        parcel.WriteParcelable(extras_.get());
}

AVMediaDescription *AVMediaDescription::Unmarshalling(Parcel& data)
{
    auto *result = new (std::nothrow) AVMediaDescription();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVMediaDescription failed");
    if (!data.ReadString(result->mediaId_)) {
        SLOGD("AVMediaDescription Unmarshalling mediaId null ");
    }
    if (!data.ReadString(result->title_)) {
        SLOGD("AVMediaDescription Unmarshalling title null ");
    }
    if (!data.ReadString(result->subtitle_)) {
        SLOGD("AVMediaDescription Unmarshalling subtitle null ");
    }
    if (!data.ReadString(result->description_)) {
        SLOGD("AVMediaDescription Unmarshalling description null ");
    }
    if (!data.ReadString(result->iconUri_)) {
        SLOGD("AVMediaDescription Unmarshalling iconUri null ");
    }
    if (!data.ReadString(result->mediaUri_)) {
        SLOGD("AVMediaDescription Unmarshalling mediaUri null ");
    }
    result->icon_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->icon_ == nullptr) {
        SLOGD("read AVMediaDescription - icon null");
    }
    result->extras_ = std::shared_ptr<AAFwk::WantParams>(data.ReadParcelable<AAFwk::WantParams>());
    if (result->extras_ == nullptr) {
        SLOGD("read AVMediaDescription - extras null");
    }
    return result;
}

void AVMediaDescription::SetMediaId(const std::string& mediaId)
{
    mediaId_ = mediaId;
}

std::string AVMediaDescription::GetMediaId() const
{
    return mediaId_;
}

void AVMediaDescription::SetTitle(const std::string& title)
{
    title_ = title;
}

std::string AVMediaDescription::GetTitle() const
{
    return title_;
}

void AVMediaDescription::SetSubtitle(const std::string& subtitle)
{
    subtitle_ = subtitle;
}

std::string AVMediaDescription::GetSubtitle() const
{
    return subtitle_;
}

void AVMediaDescription::SetDescription(const std::string& description)
{
    description_ = description;
}

std::string AVMediaDescription::GetDescription() const
{
    return description_;
}

void AVMediaDescription::SetIcon(const std::shared_ptr<AVSessionPixelMap>& icon)
{
    icon_ = icon;
}

std::shared_ptr<AVSessionPixelMap> AVMediaDescription::GetIcon() const
{
    return icon_;
}

void AVMediaDescription::SetIconUri(const std::string& iconUri)
{
    iconUri_ = iconUri;
}

std::string AVMediaDescription::GetIconUri() const
{
    return iconUri_;
}

void AVMediaDescription::SetExtras(const std::shared_ptr<AAFwk::WantParams>& extras)
{
    extras_ = extras;
}

std::shared_ptr<AAFwk::WantParams> AVMediaDescription::GetExtras() const
{
    return extras_;
}

void AVMediaDescription::SetMediaUri(const std::string& mediaId)
{
    mediaUri_ = mediaId;
}

std::string AVMediaDescription::GetMediaUri() const
{
    return mediaUri_;
}

void AVMediaDescription::Reset()
{
    mediaId_ = "";
    title_ = "";
    subtitle_ = "";
    description_ = "";
    icon_ = nullptr;
    iconUri_ = "";
    extras_ = nullptr;
    mediaUri_ = "";
}
} // namespace OHOS::AVSession
