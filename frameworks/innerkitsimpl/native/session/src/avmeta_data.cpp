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

#include "avmeta_data.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVMetaData::AVMetaData()
{
}

bool AVMetaData::Marshalling(Parcel& parcel) const
{
    return parcel.WriteString(metaMask_.to_string()) &&
        parcel.WriteString(assetId_) &&
        parcel.WriteString(title_) &&
        parcel.WriteString(artist_) &&
        parcel.WriteString(author_) &&
        parcel.WriteString(album_) &&
        parcel.WriteString(writer_) &&
        parcel.WriteString(composer_) &&
        parcel.WriteInt64(duration_) &&
        parcel.WriteParcelable(mediaImage_.get()) &&
        parcel.WriteString(mediaImageUri_) &&
        parcel.WriteString(subTitle_) &&
        parcel.WriteString(description_) &&
        parcel.WriteString(lyric_);
}

AVMetaData* AVMetaData::Unmarshalling(Parcel& data)
{
    auto result = new(std::nothrow) AVMetaData;
    if (result == nullptr) {
        return nullptr;
    }

    result->metaMask_ = MetaMaskType(data.ReadString());
    result->assetId_ = data.ReadString();
    result->title_ = data.ReadString();
    result->artist_ = data.ReadString();
    result->author_ = data.ReadString();
    result->album_ = data.ReadString();
    result->writer_ = data.ReadString();
    result->composer_ = data.ReadString();
    result->duration_ = data.ReadInt64();
    result->mediaImage_ = std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
    result->mediaImageUri_ = data.ReadString();
    result->subTitle_ = data.ReadString();
    result->description_ = data.ReadString();
    result->lyric_ = data.ReadString();

    return result;
}

void AVMetaData::SetAssetId(const std::string &assetId)
{
    assetId_ = assetId;
    metaMask_.set(META_KEY_ASSET_ID);
}

std::string AVMetaData::GetAssetId() const
{
    return assetId_;
}

void AVMetaData::SetTitle(const std::string& title)
{
    title_ = title;
    metaMask_.set(META_KEY_TITLE);
}

std::string AVMetaData::GetTitle() const
{
    return title_;
}

void AVMetaData::SetArtist(const std::string & artist)
{
    artist_ = artist;
    metaMask_.set(META_KEY_ARTIST);
}

std::string AVMetaData::GetArtist() const
{
    return artist_;
}

void AVMetaData::SetAuthor(const std::string &author)
{
    author_ = author;
    metaMask_.set(META_KEY_AUTHOR);
}

std::string AVMetaData::GetAuthor() const
{
    return author_;
}

void AVMetaData::SetAlbum(const std :: string & album)
{
    album_ = album;
    metaMask_.set(META_KEY_ALBUM);
}

std::string AVMetaData::GetAlbum() const
{
    return album_;
}

void AVMetaData::SetWriter(const std::string &wrtier)
{
    writer_ = wrtier;
    metaMask_.set(META_KEY_WRITER);
}

std::string AVMetaData::GetWriter() const
{
    return writer_;
}

void AVMetaData::SetComposer(const std::string &composer)
{
    composer_ = composer;
    metaMask_.set(META_KEY_COMPOSER);
}

std::string AVMetaData::GetComposer() const
{
    return composer_;
}

void AVMetaData::SetDuration(int64_t duration)
{
    duration_ = duration;
    metaMask_.set(META_KEY_DURATION);
}

int64_t AVMetaData::GetDuration() const
{
    return duration_;
}

void AVMetaData::SetMediaImage(const std::shared_ptr<Media::PixelMap> &mediaImage)
{
    mediaImage_ = mediaImage;
    metaMask_.set(META_KEY_MEDIA_IMAGE);
}

std::shared_ptr<Media::PixelMap> AVMetaData::GetMediaImage() const
{
    return mediaImage_;
}

void AVMetaData::SetMediaImageUri(const std::string &mediaImageUri)
{
    mediaImageUri_ = mediaImageUri;
    metaMask_.set(META_KEY_MEDIA_IMAGE_URI);
}

std::string AVMetaData::GetMediaImageUri() const
{
    return mediaImageUri_;
}

void AVMetaData::SetPublishDate(double date)
{
    publishDate_ = date;
}

double AVMetaData::GetPublishDate() const
{
    return publishDate_;
}

void AVMetaData::SetSubTitle(const std::string& subTitle)
{
    subTitle_ = subTitle;
    metaMask_.set(META_KEY_SUBTITLE);
}

std::string AVMetaData::GetSubTitle() const
{
    return subTitle_;
}

void AVMetaData::SetDescription(const std::string& description)
{
    description_ = description;
    metaMask_.set(META_KEY_DESCRIPTION);
}

std::string AVMetaData::GetDescription() const
{
    return description_;
}

void AVMetaData::SetLyric(const std :: string & lyric)
{
    lyric_ = lyric;
    metaMask_.set(META_KEY_LYRIC);
}

std::string AVMetaData::GetLyric() const
{
    return lyric_;
}

void AVMetaData::SetPreviosAssetId(const std::string &assetId)
{
    previousAssetId_ = assetId;
}

std::string AVMetaData::GetPreviosAssetId() const
{
    return previousAssetId_;
}

void AVMetaData::SetNextAssetId(const std::string &assetId)
{
    nextAssetId_ = assetId;
}

std::string AVMetaData::GetNextAssetId() const
{
    return nextAssetId_;
}

void AVMetaData::SetMetaMask(const MetaMaskType metaMask)
{
    metaMask_ = metaMask;
}

AVMetaData::MetaMaskType AVMetaData::GetMetaMask() const
{
    return metaMask_;
}

void AVMetaData::Reset()
{
    metaMask_.reset();
    assetId_ = "";
    title_ = "";
    artist_ = "";
    author_ = "";
    album_ = "";
    writer_ = "";
    composer_ = "";
    duration_ = 0;
    mediaImage_ = nullptr;
    mediaImageUri_ = "";
    subTitle_ = "";
    description_ = "";
    lyric_ = "";
    previousAssetId_ = "";
    nextAssetId_ = "";
}

bool AVMetaData::CopyToByMask(AVMetaData &metaOut) const
{
    bool result = false;
    auto intersection = metaMask_ & metaOut.metaMask_;
    for (int i = 0; i < META_KEY_MAX; i++ ) {
        if (intersection.test(i)) {
            cloneActions[i](*this, metaOut);
            result = true;
        }
    }

    return result;
}

bool AVMetaData::CopyFrom(const AVMetaData& metaIn)
{
    if (metaIn.assetId_.empty()) {
        SLOGE("assetId is empty");
        return false;
    }

    if (metaIn.assetId_ != assetId_) {
        SLOGD("assetId not equal");
        *this = metaIn;
        return true;
    }

    bool result = false;
    for (int i = 0; i < META_KEY_MAX; i++ ) {
        if (metaIn.metaMask_.test(i)) {
            cloneActions[i](metaIn, *this);
            metaMask_.set(i);
            result = true;
        }
    }

    return result;
}

void AVMetaData::CloneAssetId(const AVMetaData &from, AVMetaData &to)
{
    to.assetId_ = from.assetId_;
}

void AVMetaData::CloneTitile(const AVMetaData& from, AVMetaData& to)
{
    to.title_ = from.title_;
}

void AVMetaData::CloneArtist(const AVMetaData& from, AVMetaData& to)
{
    to.artist_ = from.artist_;
}

void AVMetaData::CloneAuthor(const AVMetaData& from, AVMetaData& to)
{
    to.author_ = from.author_;
}

void AVMetaData::CloneAlbum(const AVMetaData& from, AVMetaData& to)
{
    to.album_ = from.album_;
}

void AVMetaData::CloneWriter(const AVMetaData& from, AVMetaData& to)
{
    to.writer_ = from.writer_;
}

void AVMetaData::CloneComposer(const AVMetaData& from, AVMetaData& to)
{
    to.composer_ = from.composer_;
}

void AVMetaData::CloneDuration(const AVMetaData& from, AVMetaData& to)
{
    to.duration_ = from.duration_;
}

void AVMetaData::CloneMediaImage(const AVMetaData& from, AVMetaData& to)
{
    to.mediaImage_ = from.mediaImage_;
}

void AVMetaData::CloneMediaImageUri(const AVMetaData& from, AVMetaData& to)
{
    to.mediaImageUri_ = from.mediaImageUri_;
}

void AVMetaData::ClonePublishData(const AVMetaData &from, AVMetaData &to)
{
    to.publishDate_ = from.publishDate_;
}

void AVMetaData::CloneSubTitile(const AVMetaData& from, AVMetaData& to)
{
    to.subTitle_ = from.subTitle_;
}

void AVMetaData::CloneDescriptiion(const AVMetaData& from, AVMetaData& to)
{
    to.description_ = from.description_;
}

void AVMetaData::CloneLyric(const AVMetaData& from, AVMetaData& to)
{
    to.lyric_ = from.lyric_;
}

void AVMetaData::ClonePreviousAssetId(const AVMetaData &from, AVMetaData &to)
{
    to.previousAssetId_ = from.assetId_;
}

void AVMetaData::CloneNextAssetId(const AVMetaData &from, AVMetaData &to)
{
    to.nextAssetId_ = from.nextAssetId_;
}
} // namespace OHOS::AVSession