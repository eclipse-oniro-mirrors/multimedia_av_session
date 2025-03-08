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
        parcel.WriteString(mediaType_) &&
        parcel.WriteInt32(mediaSize_) &&
        parcel.WriteString(albumTitle_) &&
        parcel.WriteString(albumCoverUri_) &&
        parcel.WriteString(lyricContent_) &&
        parcel.WriteString(lyricUri_) &&
        parcel.WriteString(artist_) &&
        parcel.WriteString(mediaUri_) &&
        fdSrc_.WriteToParcel(parcel)&&
        parcel.WriteInt32(duration_) &&
        parcel.WriteInt32(startPosition_) &&
        parcel.WriteInt32(creditsPosition_) &&
        parcel.WriteString(appName_) &&
        parcel.WriteParcelable(icon_.get()) &&
        parcel.WriteParcelable(extras_.get()) &&
        parcel.WriteString(drmScheme_) &&
        dataSrc_.WriteToParcel(parcel);
}

AVMediaDescription *AVMediaDescription::Unmarshalling(Parcel& data)
{
    auto *result = new (std::nothrow) AVMediaDescription();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVMediaDescription failed");
    data.ReadString(result->mediaId_);
    data.ReadString(result->title_);
    data.ReadString(result->subtitle_);
    data.ReadString(result->description_);
    data.ReadString(result->iconUri_);
    data.ReadString(result->mediaType_);
    data.ReadInt32(result->mediaSize_);
    data.ReadString(result->albumTitle_);
    data.ReadString(result->albumCoverUri_);
    data.ReadString(result->lyricContent_);
    data.ReadString(result->lyricUri_);
    data.ReadString(result->artist_);
    data.ReadString(result->mediaUri_);
    result->fdSrc_.ReadFromParcel(data);
    data.ReadInt32(result->duration_);
    data.ReadInt32(result->startPosition_);
    data.ReadInt32(result->creditsPosition_);
    data.ReadString(result->appName_);
    result->icon_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->icon_ == nullptr) {
        SLOGD("read AVMediaDescription - icon null");
    }
    result->extras_ = std::shared_ptr<AAFwk::WantParams>(data.ReadParcelable<AAFwk::WantParams>());
    if (result->extras_ == nullptr) {
        SLOGD("read AVMediaDescription - extras null");
    }
    data.ReadString(result->drmScheme_);
    result->dataSrc_.ReadFromParcel(data);
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

void AVMediaDescription::SetMediaUri(const std::string& mediaUri)
{
    mediaUri_ = mediaUri;
}

std::string AVMediaDescription::GetMediaUri() const
{
    return mediaUri_;
}

void AVMediaDescription::SetFdSrc(const AVFileDescriptor& fdSrc)
{
    fdSrc_ = fdSrc;
}

AVFileDescriptor AVMediaDescription::GetFdSrc() const
{
    return fdSrc_;
}
void AVMediaDescription::SetMediaType(const std::string& mediaType)
{
    mediaType_ = mediaType;
}

std::string AVMediaDescription::GetMediaType() const
{
    return mediaType_;
}

void AVMediaDescription::SetMediaSize(const int32_t mediaSize)
{
    mediaSize_ = mediaSize;
}

int32_t AVMediaDescription::GetMediaSize() const
{
    return mediaSize_;
}

void AVMediaDescription::SetAlbumTitle(const std::string& albumTitle)
{
    albumTitle_ = albumTitle;
}

std::string AVMediaDescription::GetAlbumTitle() const
{
    return albumTitle_;
}

void AVMediaDescription::SetAlbumCoverUri(const std::string& albumCoverUri)
{
    albumCoverUri_ = albumCoverUri;
}

std::string AVMediaDescription::GetAlbumCoverUri() const
{
    return albumCoverUri_;
}

void AVMediaDescription::SetLyricContent(const std::string& lyricContent)
{
    lyricContent_ = lyricContent;
}

std::string AVMediaDescription::GetLyricContent() const
{
    return lyricContent_;
}

void AVMediaDescription::SetLyricUri(const std::string& lyricUri)
{
    lyricUri_ = lyricUri;
}

std::string AVMediaDescription::GetLyricUri() const
{
    return lyricUri_;
}

void AVMediaDescription::SetArtist(const std::string& artist)
{
    artist_ = artist;
}

std::string AVMediaDescription::GetArtist() const
{
    return artist_;
}

void AVMediaDescription::SetDuration(const int32_t duration)
{
    duration_ = duration;
}

int32_t AVMediaDescription::GetDuration() const
{
    return duration_;
}

void AVMediaDescription::SetStartPosition(const int32_t startPosition)
{
    startPosition_ = startPosition;
}

int32_t AVMediaDescription::GetStartPosition() const
{
    return startPosition_;
}

void AVMediaDescription::SetCreditsPosition(const int32_t creditsPosition)
{
    creditsPosition_ = creditsPosition;
}

int32_t AVMediaDescription::GetCreditsPosition() const
{
    return creditsPosition_;
}

void AVMediaDescription::SetAppName(const std::string& appName)
{
    appName_ = appName;
}

std::string AVMediaDescription::GetAppName() const
{
    return appName_;
}

void AVMediaDescription::SetDrmScheme(const std::string& drmScheme)
{
    drmScheme_ = drmScheme;
}
 
std::string AVMediaDescription::GetDrmScheme() const
{
    return drmScheme_;
}

bool AVMediaDescription::IsValid() const
{
    return !(mediaId_.empty());
}

void AVMediaDescription::SetDataSrc(const AVDataSrcDescriptor& dataSrc)
{
    dataSrc_ = dataSrc;
}

AVDataSrcDescriptor AVMediaDescription::GetDataSrc() const
{
    return dataSrc_;
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
    mediaType_ = "";
    mediaSize_ = 0;
    albumTitle_ = "";
    albumCoverUri_ = "";
    lyricContent_ = "";
    lyricUri_ = "";
    artist_ = "";
    mediaUri_ = "";
    AVFileDescriptor fdSrc;
    fdSrc_ = fdSrc;
    duration_ = 0;
    startPosition_ = 0;
    creditsPosition_ = 0;
    appName_ = "";
    drmScheme_ = "";
    AVDataSrcDescriptor dataSrc;
    dataSrc_ = dataSrc;
}
} // namespace OHOS::AVSession
