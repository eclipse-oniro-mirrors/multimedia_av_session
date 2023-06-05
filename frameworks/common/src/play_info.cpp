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

#include "play_info.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool PlayInfo::Marshalling(Parcel& parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(mediaId_), false, "write id failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(mediaName_), false, "write name failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(mediaUrl_), false, "write url failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(mediaType_), false, "write type failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(startPosition_), false, "write position failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt64(duration_), false, "write duration failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(albumCoverUrl_), false, "write albumUrl failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(albumTitle_), false, "write albumTitle failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(artist_), false, "write artist_ failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(lyricUrl_), false, "write lyricUrl failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(lyricContent_), false, "write lyricContent failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(icon_), false, "write icon failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteParcelable(iconImage_.get()), false, "write iconImage failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(iconUri_), false, "write iconUrl failed");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(appName_), false, "write appName failed");
    return true;
}

PlayInfo *PlayInfo::Unmarshalling(Parcel& data)
{
    auto *result = new (std::nothrow) PlayInfo();

    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new PlayInfo failed");

    
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->mediaId_), nullptr, "Read id failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->mediaName_), nullptr, "Read name failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->mediaUrl_), nullptr, "Read url failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->mediaType_), nullptr, "Read type failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(result->startPosition_), nullptr, "Read position failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(result->duration_), nullptr, "Read duration failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->albumCoverUrl_), nullptr, "Read albumUrl failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->albumTitle_), nullptr, "Read albumTitle failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->artist_), nullptr, "Read artist failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->lyricUrl_), nullptr, "Read lyricUrl failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->lyricContent_), nullptr, "Read lyricContent failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->icon_), nullptr, "Read icon failed");
    result->iconImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->iconUri_), nullptr, "Read iconUrl failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(result->appName_), nullptr, "Read appName failed");

    return result;
}

void PlayInfo::SetMediaId(const std::string& mediaId)
{
    mediaId_ = mediaId;
}

std::string PlayInfo::GetMediaId() const
{
    return mediaId_;
}

void PlayInfo::SetMediaName(const std::string& mediaName)
{
    mediaName_ = mediaName;
}

std::string PlayInfo::GetMediaName() const
{
    return mediaName_;
}

void PlayInfo::SetMediaUrl(const std::string& mediaUrl)
{
    mediaUrl_ = mediaUrl;
}

std::string PlayInfo::GetMediaUrl() const
{
    return mediaUrl_;
}

void PlayInfo::SetMediaType(const std::string& mediaType)
{
    mediaType_ = mediaType;
}

std::string PlayInfo::GetMediaType() const
{
    return mediaType_;
}

void PlayInfo::SetStartPosition(const int32_t startPosition)
{
    startPosition_ = startPosition;
}

int32_t PlayInfo::GetStartPosition() const
{
    return startPosition_;
}

void PlayInfo::SetDuration(const int32_t duration)
{
    duration_ = duration;
}

int32_t PlayInfo::GetDuration() const
{
    return duration_;
}

void PlayInfo::SetAlbumCoverUrl(const std::string& albumCoverUrl)
{
    albumCoverUrl_ = albumCoverUrl;
}

std::string PlayInfo::GetAlbumCoverUrl() const
{
    return albumCoverUrl_;
}

void PlayInfo::SetAlbumTitle(const std::string& albumTitle)
{
    albumTitle_ = albumTitle;
}

std::string PlayInfo::GetAlbumTitle() const
{
    return albumTitle_;
}

void PlayInfo::SetArtist(const std::string& artist)
{
    artist_ = artist;
}

std::string PlayInfo::GetArtist() const
{
    return artist_;
}

void PlayInfo::SetLyricUrl(const std::string& lyricUrl)
{
    lyricUrl_ = lyricUrl;
}

std::string PlayInfo::GetLyricUrl() const
{
    return lyricUrl_;
}

void PlayInfo::SetLyricContent(const std::string& lyricContent)
{
    lyricContent_ = lyricContent;
}

std::string PlayInfo::GetLyricContent() const
{
    return lyricContent_;
}

void PlayInfo::SetIcon(const std::string& icon)
{
    icon_ = icon;
}

std::string PlayInfo::GetIcon() const
{
    return icon_;
}

void PlayInfo::SetIconImage(const std::shared_ptr<AVSessionPixelMap>& iconImage)
{
    iconImage_ = iconImage;
}

std::shared_ptr<AVSessionPixelMap> PlayInfo::GetIconImage() const
{
    return iconImage_;
}

void PlayInfo::SetIconUri(const std::string& iconUri)
{
    iconUri_ = iconUri;
}

std::string PlayInfo::GetIconUri() const
{
    return iconUri_;
}

void PlayInfo::SetAppName(const std::string& appName)
{
    appName_ = appName;
}

std::string PlayInfo::GetAppName() const
{
    return appName_;
}

bool PlayInfo::IsValid() const
{
    return !(mediaId_.empty());
}

void PlayInfo::Reset()
{
    mediaId_ = "";
    mediaName_ = "";
    mediaUrl_ = "";
    mediaType_ = "";
    startPosition_ = 0;
    duration_ = 0;
    albumCoverUrl_ = "";
    albumTitle_ = "";
    artist_ = "";
    lyricUrl_ = "";
    lyricContent_ = "";
    icon_ = "";
    iconImage_ = nullptr;
    iconUri_ = "";
    appName_ = "";
}
} // namespace OHOS::AVSession
