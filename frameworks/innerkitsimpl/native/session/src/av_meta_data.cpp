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
#include "av_meta_data.h"

namespace OHOS::AVSession {
AVMetaData::AVMetaData()
    : Parcelable(true)
{
}

bool AVMetaData::Marshalling(Parcel& parcel) const
{
    return false;
}

AVMetaData* AVMetaData::Unmarshalling(Parcel& data)
{
    return nullptr;
}

void AVMetaData::SetMediaId(const std::string &mediaId)
{
    mediaId_ = mediaId;
}

std::string AVMetaData::GetMediaId() const
{
    return mediaId_;
}

void AVMetaData::SetTitle(const std::string& title)
{
    title_ = title;
}

std::string AVMetaData::GetTitle() const
{
    return title_;
}

void AVMetaData::SetArtist(const std::string & artist)
{
    artist_ = artist;
}

std::string AVMetaData::GetArtist() const
{
    return artist_;
}

void AVMetaData::SetAuthor(const std::string &author)
{
    author_ = author;
}

std::string AVMetaData::GetAuthor() const
{
    return author_;
}

void AVMetaData::SetAlbum(const std :: string & album)
{
    album_ = album;
}

std::string AVMetaData::GetAlbum() const
{
    return album_;
}

void AVMetaData::SetWriter(const std::string &wrtier)
{
    writer_ = wrtier;
}

std::string AVMetaData::GetWriter() const
{
    return writer_;
}

void AVMetaData::SetComposer(const std::string &composer)
{
    composer_ = composer;
}

std::string AVMetaData::GetComposer() const
{
    return composer_;
}

void AVMetaData::SetDuration(int64_t duration)
{
    duration_ = duration;
}

int64_t AVMetaData::GetDuration() const
{
    return duration_;
}

void AVMetaData::SetMediaImage(const std::shared_ptr<Media::PixelMap> &mediaImage)
{
    mediaImage_ = mediaImage;
}

std::shared_ptr<Media::PixelMap> AVMetaData::GetMediaImage() const
{
    return mediaImage_;
}

void AVMetaData::SetMediaImageUri(const std::string &mediaImageUri)
{
    mediaImageUri_ = mediaImageUri;
}

std::string AVMetaData::GetMediaImageUri() const
{
    return mediaImageUri_;
}

void AVMetaData::SetAppIcon(const std::shared_ptr<Media::PixelMap> &appIcon)
{
    appIcon_ = appIcon;
}

std::shared_ptr<Media::PixelMap> AVMetaData::GetAppIcon() const
{
    return appIcon_;
}

void AVMetaData::SetAppIconUri(const std::string& appIconUri)
{
    appIconUri_ = appIconUri;
}

std::string AVMetaData::GetAppIconUri() const
{
    return appIconUri_;
}

void AVMetaData::SetSubTitle(const std :: string & subTitle)
{
    subTitle_ = subTitle;
}

std::string AVMetaData::GetSubTitle() const
{
    return subTitle_;
}

void AVMetaData::SetDescription(const std :: string & description)
{
    description_ = description;
}

std::string AVMetaData::GetDescription() const
{
    return description_;
}

void AVMetaData::SetLyric(const std :: string & lyric)
{
    lyric_ = lyric;
}

std::string AVMetaData::GetLyric() const
{
    return lyric_;
}

void AVMetaData::SetMetaMask(const MetaMaskType metaMask)
{
    metaMask_ = metaMask;
}

AVMetaData::MetaMaskType AVMetaData::GetMetaMask() const
{
    return metaMask_;
}

void AVMetaData::ClearChange()
{
    metaMask_.reset();
}

bool AVMetaData::CopyToByMask(AVMetaData &metaOut)
{
    return false;
}

bool AVMetaData::CopyFrom(const AVMetaData& metaIn)
{
    return false;
}

void AVMetaData::CloneMediaId(const AVMetaData &from, AVMetaData &to)
{
    to.mediaId_ = from.mediaId_;
}
} // namespace OHOS::AVSession