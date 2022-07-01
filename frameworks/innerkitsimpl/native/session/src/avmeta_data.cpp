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
        parcel.WriteString(mediaImageUri_) &&
        parcel.WriteDouble(publishDate_) &&
        parcel.WriteString(subTitle_) &&
        parcel.WriteString(description_) &&
        parcel.WriteString(lyric_) &&
        parcel.WriteString(previousAssetId_) &&
        parcel.WriteString(nextAssetId_) &&
        parcel.WriteParcelable(mediaImage_.get());
}

AVMetaData *AVMetaData::Unmarshalling(Parcel& data)
{
    std::string mask;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(mask) && mask.length() == META_KEY_MAX, nullptr, "mask not valid");
    CHECK_AND_RETURN_RET_LOG(mask.find_first_not_of("01") == std::string::npos, nullptr, "mask string not 0 or 1");

    auto *result = new (std::nothrow) AVMetaData();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVMetaData failed");
    result->metaMask_ = MetaMaskType(mask);
    if (!data.ReadString(result->assetId_) ||
        !data.ReadString(result->title_) ||
        !data.ReadString(result->artist_) ||
        !data.ReadString(result->author_) ||
        !data.ReadString(result->album_) ||
        !data.ReadString(result->writer_) ||
        !data.ReadString(result->composer_) ||
        !data.ReadInt64(result->duration_) ||
        !data.ReadString(result->mediaImageUri_) ||
        !data.ReadDouble(result->publishDate_) ||
        !data.ReadString(result->subTitle_) ||
        !data.ReadString(result->description_) ||
        !data.ReadString(result->lyric_) ||
        !data.ReadString(result->previousAssetId_) ||
        !data.ReadString(result->nextAssetId_)) {
        SLOGE("read AVMetaData failed");
        delete result;
        return nullptr;
    }
    result->mediaImage_ = std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
    if (result->metaMask_.test(META_KEY_MEDIA_IMAGE) && result->mediaImage_ == nullptr) {
        SLOGE("read PixelMap failed");
        delete result;
        return nullptr;
    }
    return result;
}

void AVMetaData::SetAssetId(const std::string& assetId)
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

void AVMetaData::SetArtist(const std::string& artist)
{
    artist_ = artist;
    metaMask_.set(META_KEY_ARTIST);
}

std::string AVMetaData::GetArtist() const
{
    return artist_;
}

void AVMetaData::SetAuthor(const std::string& author)
{
    author_ = author;
    metaMask_.set(META_KEY_AUTHOR);
}

std::string AVMetaData::GetAuthor() const
{
    return author_;
}

void AVMetaData::SetAlbum(const std::string& album)
{
    album_ = album;
    metaMask_.set(META_KEY_ALBUM);
}

std::string AVMetaData::GetAlbum() const
{
    return album_;
}

void AVMetaData::SetWriter(const std::string& writer)
{
    writer_ = writer;
    metaMask_.set(META_KEY_WRITER);
}

std::string AVMetaData::GetWriter() const
{
    return writer_;
}

void AVMetaData::SetComposer(const std::string& composer)
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
    if (duration < AVMetaData::DURATION_ALWAYS_PLAY) {
        SLOGE("invalid duration");
        return;
    }
    duration_ = duration;
    metaMask_.set(META_KEY_DURATION);
}

int64_t AVMetaData::GetDuration() const
{
    return duration_;
}

void AVMetaData::SetMediaImage(const std::shared_ptr<Media::PixelMap>& mediaImage)
{
    mediaImage_ = mediaImage;
    metaMask_.set(META_KEY_MEDIA_IMAGE);
}

std::shared_ptr<Media::PixelMap> AVMetaData::GetMediaImage() const
{
    return mediaImage_;
}

void AVMetaData::SetMediaImageUri(const std::string& mediaImageUri)
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
    if (date < 0) {
        SLOGE("invalid publish date");
        return;
    }
    publishDate_ = date;
    metaMask_.set(META_KEY_PUBLISH_DATE);
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

void AVMetaData::SetLyric(const std::string& lyric)
{
    lyric_ = lyric;
    metaMask_.set(META_KEY_LYRIC);
}

std::string AVMetaData::GetLyric() const
{
    return lyric_;
}

void AVMetaData::SetPreviousAssetId(const std::string& assetId)
{
    previousAssetId_ = assetId;
    metaMask_.set(META_KEY_PREVIOUS_ASSET_ID);
}

std::string AVMetaData::GetPreviousAssetId() const
{
    return previousAssetId_;
}

void AVMetaData::SetNextAssetId(const std::string& assetId)
{
    nextAssetId_ = assetId;
    metaMask_.set(META_KEY_NEXT_ASSET_ID);
}

std::string AVMetaData::GetNextAssetId() const
{
    return nextAssetId_;
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
    publishDate_ = 0;
    subTitle_ = "";
    description_ = "";
    lyric_ = "";
    previousAssetId_ = "";
    nextAssetId_ = "";
}

bool AVMetaData::CopyToByMask(MetaMaskType& mask, AVMetaData& metaOut) const
{
    bool result = false;
    auto intersection = metaMask_ & mask;
    for (int i = 0; i < META_KEY_MAX; i++) {
        if (intersection.test(i)) {
            cloneActions[i](*this, metaOut);
            metaOut.metaMask_.set(i);
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
    for (int i = 0; i < META_KEY_MAX; i++) {
        if (metaIn.metaMask_.test(i)) {
            cloneActions[i](metaIn, *this);
            metaMask_.set(i);
            result = true;
        }
    }

    return result;
}

bool AVMetaData::IsValid() const
{
    return duration_ >= AVMetaData::DURATION_ALWAYS_PLAY && publishDate_ >= 0;
}

void AVMetaData::CloneAssetId(const AVMetaData& from, AVMetaData& to)
{
    to.assetId_ = from.assetId_;
}

void AVMetaData::CloneTitle(const AVMetaData& from, AVMetaData& to)
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

void AVMetaData::CloneSubTitle(const AVMetaData& from, AVMetaData& to)
{
    to.subTitle_ = from.subTitle_;
}

void AVMetaData::CloneDescription(const AVMetaData& from, AVMetaData& to)
{
    to.description_ = from.description_;
}

void AVMetaData::CloneLyric(const AVMetaData& from, AVMetaData& to)
{
    to.lyric_ = from.lyric_;
}

void AVMetaData::ClonePreviousAssetId(const AVMetaData &from, AVMetaData &to)
{
    to.previousAssetId_ = from.previousAssetId_;
}

void AVMetaData::CloneNextAssetId(const AVMetaData &from, AVMetaData &to)
{
    to.nextAssetId_ = from.nextAssetId_;
}
} // namespace OHOS::AVSession