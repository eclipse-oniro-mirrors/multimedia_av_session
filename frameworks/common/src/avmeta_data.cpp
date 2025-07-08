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
    return WriteToParcel(static_cast<MessageParcel&>(parcel));
}

bool AVMetaData::WriteToParcel(MessageParcel& parcel) const
{
    int mediaImageLength = 0;
    std::vector<uint8_t> mediaImageBuffer;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = GetMediaImage();
    if (mediaPixelMap != nullptr) {
        mediaImageBuffer = mediaPixelMap->GetInnerImgBuffer();
        mediaImageLength = static_cast<int>(mediaImageBuffer.size());
        SetMediaLength(mediaImageLength);
    }

    int avQueueImageLength = 0;
    std::vector<uint8_t> avQueueImageBuffer;
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = GetAVQueueImage();
    if (avQueuePixelMap != nullptr) {
        avQueueImageBuffer = avQueuePixelMap->GetInnerImgBuffer();
        avQueueImageLength = static_cast<int>(avQueueImageBuffer.size());
        SetAVQueueLength(avQueueImageLength);
    }
    int32_t twoImageLength = mediaImageLength + avQueueImageLength;
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(twoImageLength), false, "write twoImageLength failed");
    CHECK_AND_RETURN_RET_LOG(MarshallingExceptImg(parcel), false, "MarshallingExceptImg failed");

    int32_t maxImageSize = 10 * 1024 *1024;
    bool isImageValid = twoImageLength > 0 && twoImageLength <= maxImageSize;
    CHECK_AND_RETURN_RET(isImageValid, true);

    unsigned char *buffer = new (std::nothrow) unsigned char[twoImageLength];
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, false, "new buffer failed");
    for (int i = 0; i < mediaImageLength; i++) {
        buffer[i] = mediaImageBuffer[i];
    }

    for (int j = mediaImageLength, k = 0; j < twoImageLength && k < avQueueImageLength; j++, k++) {
        buffer[j] = avQueueImageBuffer[k];
    }

    bool retForWriteRawData = parcel.WriteRawData(buffer, twoImageLength);
    SLOGD("write rawdata ret %{public}d", retForWriteRawData);
    delete[] buffer;
    return retForWriteRawData;
}

AVMetaData *AVMetaData::Unmarshalling(Parcel& in)
{
    AVMetaData* metaData = new (std::nothrow) AVMetaData();
    CHECK_AND_RETURN_RET_LOG(metaData != nullptr, nullptr, "create metaData failed");
    int twoImageLength = 0;
    if (!in.ReadInt32(twoImageLength)) {
        SLOGI("read twoImageLength failed");
        delete metaData;
        metaData = nullptr;
        return nullptr;
    }
    if (metaData->UnmarshallingExceptImg(static_cast<MessageParcel&>(in))) {
        SLOGI("UnmarshallingExceptImg failed");
        delete metaData;
        metaData = nullptr;
        return nullptr;
    }
    int32_t maxImageSize = 10 * 1024 *1024;
    bool isImageValid = twoImageLength > 0 && twoImageLength <= maxImageSize;
    CHECK_AND_RETURN_RET(isImageValid, metaData);
    if (!metaData->ReadFromParcel(static_cast<MessageParcel&>(in), twoImageLength)) {
        SLOGI("ReadFromParcel failed");
        delete metaData;
        metaData = nullptr;
        return nullptr;
    }
    return metaData;
}

bool AVMetaData::ReadFromParcel(MessageParcel& in, int32_t twoImageLength)
{
    const char *buffer = nullptr;
    buffer = reinterpret_cast<const char *>(in.ReadRawData(twoImageLength));
    int mediaImageLength = GetMediaLength();
    CHECK_AND_RETURN_RET_LOG(
        buffer != nullptr && mediaImageLength >= 0 && mediaImageLength <= twoImageLength,
        false, "readRawData failed");
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> mediaImageBuffer;
    for (int i = 0; i < mediaImageLength; i++) {
        mediaImageBuffer.push_back((uint8_t)buffer[i]);
    }
    mediaPixelMap->SetInnerImgBuffer(mediaImageBuffer);
    SetMediaImage(mediaPixelMap);

    CHECK_AND_RETURN_RET_LOG(twoImageLength > mediaImageLength, true,
                             "twoImageLength <= mediaImageLength");
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
    std::vector<uint8_t> avQueueImageBuffer;
    for (int j = mediaImageLength; j < twoImageLength; j++) {
        avQueueImageBuffer.push_back((uint8_t)buffer[j]);
    }
    avQueuePixelMap->SetInnerImgBuffer(avQueueImageBuffer);
    SetAVQueueImage(avQueuePixelMap);
    return true;
}

bool AVMetaData::MarshallingExceptImg(MessageParcel& data) const
{
    bool ret = data.WriteString(metaMask_.to_string()) &&
        data.WriteString(assetId_) &&
        data.WriteString(title_) &&
        data.WriteString(artist_) &&
        data.WriteString(author_) &&
        data.WriteString(avQueueName_) &&
        data.WriteString(avQueueId_) &&
        data.WriteString(avQueueImageUri_) &&
        data.WriteString(album_) &&
        data.WriteString(writer_) &&
        data.WriteString(composer_) &&
        data.WriteInt64(duration_) &&
        data.WriteString(mediaImageUri_) &&
        data.WriteDouble(publishDate_) &&
        data.WriteString(subTitle_) &&
        data.WriteString(description_) &&
        data.WriteString(lyric_) &&
        data.WriteString(singleLyricText_) &&
        data.WriteString(previousAssetId_) &&
        data.WriteString(nextAssetId_) &&
        data.WriteInt32(skipIntervals_) &&
        data.WriteInt32(filter_) &&
        data.WriteInt32(mediaLength_) &&
        data.WriteInt32(avQueueLength_) &&
        data.WriteInt32(displayTags_) &&
        data.WriteParcelable(bundleIcon_.get());
        WriteDrmSchemes(data);
    SLOGD("MarshallingExceptImg without small img ret %{public}d", static_cast<int>(ret));
    return ret;
}

bool AVMetaData::UnmarshallingExceptImg(MessageParcel& data)
{
    std::string mask;
    data.ReadString(mask);
    int32_t maskSize = static_cast<int32_t>(mask.size());
    if (maskSize <= 0 || maskSize > META_KEY_MAX) {
        SLOGE("get err mask, return");
        return false;
    }
    SLOGD("get mask with %{public}s", mask.c_str());
    for (int32_t i = 0; i < maskSize; ++i) {
        if (mask[i] == '1') {
            metaMask_.flip(maskSize - i - 1);
        }
    }

    bool ret = !data.ReadString(assetId_) ||
        !data.ReadString(title_) ||
        !data.ReadString(artist_) ||
        !data.ReadString(author_) ||
        !data.ReadString(avQueueName_) ||
        !data.ReadString(avQueueId_) ||
        !data.ReadString(avQueueImageUri_) ||
        !data.ReadString(album_) ||
        !data.ReadString(writer_) ||
        !data.ReadString(composer_) ||
        !data.ReadInt64(duration_) ||
        !data.ReadString(mediaImageUri_) ||
        !data.ReadDouble(publishDate_) ||
        !data.ReadString(subTitle_) ||
        !data.ReadString(description_) ||
        !data.ReadString(lyric_) ||
        !data.ReadString(singleLyricText_) ||
        !data.ReadString(previousAssetId_) ||
        !data.ReadString(nextAssetId_) ||
        !data.ReadInt32(skipIntervals_) ||
        !data.ReadInt32(filter_) ||
        !data.ReadInt32(mediaLength_) ||
        !data.ReadInt32(avQueueLength_) ||
        !data.ReadInt32(displayTags_);
    bundleIcon_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    CHECK_AND_RETURN_RET_LOG(!metaMask_.test(META_KEY_BUNDLE_ICON) || bundleIcon_ != nullptr,
        false, "read bundle icon failed");
    ret = ret || !ReadDrmSchemes(data);
    SLOGD("UnmarshallingExceptImg with drm but no small img ret %{public}d", static_cast<int>(ret));
    return ret;
}

bool AVMetaData::WriteDrmSchemes(Parcel& parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(drmSchemes_.size()), false,
        "write drmSchemes size failed");
    for (auto drmScheme : drmSchemes_) {
        CHECK_AND_RETURN_RET_LOG(parcel.WriteString(drmScheme), false, "write drmScheme failed");
    }
    return true;
}

bool AVMetaData::WriteDrmSchemes(MessageParcel& parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(drmSchemes_.size()), false,
        "write drmSchemes size failed");
    for (auto drmScheme : drmSchemes_) {
        CHECK_AND_RETURN_RET_LOG(parcel.WriteString(drmScheme), false, "write drmScheme failed");
    }
    return true;
}

bool AVMetaData::ReadDrmSchemes(Parcel& parcel, AVMetaData* metaData)
{
    int32_t drmSchemesLen = 0;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(drmSchemesLen), false, "read drmSchemesLen failed");
    std::vector<std::string> drmSchemes;
    int32_t maxDrmSchemesLen = 10;
    CHECK_AND_RETURN_RET_LOG((drmSchemesLen >= 0) &&
        (drmSchemesLen <= maxDrmSchemesLen), false, "drmSchemesLen is illegal");
    for (int i = 0; i < drmSchemesLen; i++) {
        std::string drmScheme;
        CHECK_AND_RETURN_RET_LOG(parcel.ReadString(drmScheme), false, "read drmScheme failed");
        drmSchemes.emplace_back(drmScheme);
    }
    metaData->drmSchemes_ = drmSchemes;
    return true;
}

bool AVMetaData::ReadDrmSchemes(MessageParcel& parcel)
{
    int32_t drmSchemesLen = 0;
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(drmSchemesLen), false, "read drmSchemesLen failed");
    std::vector<std::string> drmSchemes;
    int32_t maxDrmSchemesLen = 10;
    CHECK_AND_RETURN_RET_LOG((drmSchemesLen >= 0) &&
        (drmSchemesLen <= maxDrmSchemesLen), false, "drmSchemesLen is illegal");
    for (int i = 0; i < drmSchemesLen; i++) {
        std::string drmScheme;
        CHECK_AND_RETURN_RET_LOG(parcel.ReadString(drmScheme), false, "read drmScheme failed");
        drmSchemes.emplace_back(drmScheme);
    }
    drmSchemes_ = drmSchemes;
    return true;
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

void AVMetaData::SetAVQueueName(const std::string& avQueueName)
{
    avQueueName_ = avQueueName;
    metaMask_.set(META_KEY_AVQUEUE_NAME);
}

std::string AVMetaData::GetAVQueueName() const
{
    return avQueueName_;
}

void AVMetaData::SetAVQueueId(const std::string& avQueueId)
{
    avQueueId_ = avQueueId;
    metaMask_.set(META_KEY_AVQUEUE_ID);
}

std::string AVMetaData::GetAVQueueId() const
{
    return avQueueId_;
}

void AVMetaData::SetAVQueueImage(const std::shared_ptr<AVSessionPixelMap>& avQueueImage)
{
    avQueueImage_ = avQueueImage;
    metaMask_.set(META_KEY_AVQUEUE_IMAGE);
}

std::shared_ptr<AVSessionPixelMap> AVMetaData::GetAVQueueImage() const
{
    return avQueueImage_;
}

void AVMetaData::SetBundleIcon(const std::shared_ptr<AVSessionPixelMap>& bundleIcon)
{
    bundleIcon_ = bundleIcon;
    metaMask_.set(META_KEY_BUNDLE_ICON);
}

std::shared_ptr<AVSessionPixelMap> AVMetaData::GetBundleIcon() const
{
    return bundleIcon_;
}

void AVMetaData::SetAVQueueImageUri(const std::string& avQueueImageUri)
{
    avQueueImageUri_ = avQueueImageUri;
    metaMask_.set(META_KEY_AVQUEUE_IMAGE_URI);
}

std::string AVMetaData::GetAVQueueImageUri() const
{
    return avQueueImageUri_;
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
        SLOGW("invalid duration");
    }
    duration_ = duration;
    metaMask_.set(META_KEY_DURATION);
}

int64_t AVMetaData::GetDuration() const
{
    return duration_;
}

void AVMetaData::SetMediaImage(const std::shared_ptr<AVSessionPixelMap>& mediaImage)
{
    mediaImage_ = mediaImage;
    metaMask_.set(META_KEY_MEDIA_IMAGE);
}

std::shared_ptr<AVSessionPixelMap> AVMetaData::GetMediaImage() const
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
        SLOGW("invalid publish date");
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

void AVMetaData::SetSingleLyricText(const std::string& singleLyricText)
{
    singleLyricText_ = singleLyricText;
    metaMask_.set(META_KEY_SINGLE_LYRIC_TEXT);
}

std::string AVMetaData::GetSingleLyricText() const
{
    return singleLyricText_;
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

void AVMetaData::SetSkipIntervals(int32_t skipIntervals)
{
    SLOGD("SetSkipIntervals %{public}d", static_cast<int32_t>(skipIntervals));
    skipIntervals_ = skipIntervals;
    metaMask_.set(META_KEY_SKIP_INTERVALS);
}

int32_t AVMetaData::GetSkipIntervals() const
{
    SLOGD("GetSkipIntervals %{public}d", static_cast<int32_t>(skipIntervals_));
    return skipIntervals_;
}

void AVMetaData::SetFilter(int32_t filter)
{
    SLOGD("SetFilter %{public}d", static_cast<int32_t>(filter));
    filter_ = filter;
    metaMask_.set(META_KEY_FILTER);
}

int32_t AVMetaData::GetFilter() const
{
    SLOGD("GetFilter %{public}d", static_cast<int32_t>(filter_));
    return filter_;
}

void AVMetaData::SetMediaLength(int32_t mediaLength) const
{
    mediaLength_ = mediaLength;
}

int32_t AVMetaData::GetMediaLength() const
{
    return mediaLength_;
}

void AVMetaData::SetAVQueueLength(int32_t avQueueLength) const
{
    avQueueLength_ = avQueueLength;
}

int32_t AVMetaData::GetAVQueueLength() const
{
    return avQueueLength_;
}

void AVMetaData::SetDisplayTags(int32_t displayTags)
{
    SLOGD("SetDisplayTags %{public}d", static_cast<int32_t>(displayTags));
    displayTags_ = displayTags;
    metaMask_.set(META_KEY_DISPLAY_TAGS);
}

int32_t AVMetaData::GetDisplayTags() const
{
    SLOGD("GetDisplayTags %{public}d", static_cast<int32_t>(displayTags_));
    return displayTags_;
}

void AVMetaData::SetDrmSchemes(std::vector<std::string> drmSchemes)
{
    drmSchemes_ = drmSchemes;
    metaMask_.set(META_KEY_DRM_SCHEMES);
}

std::vector<std::string> AVMetaData::GetDrmSchemes() const
{
    return drmSchemes_;
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
    avQueueName_ = "";
    avQueueId_ = "";
    avQueueImage_ = nullptr;
    avQueueImageUri_ = "";
    bundleIcon_ = nullptr;
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
    singleLyricText_ = "";
    previousAssetId_ = "";
    nextAssetId_ = "";
    skipIntervals_ = SECONDS_15;
    displayTags_ = 0;
    drmSchemes_.clear();
}

void AVMetaData::ResetToBaseMeta()
{
    metaMask_.reset();
    metaMask_.set(META_KEY_ASSET_ID);
    metaMask_.set(META_KEY_MEDIA_IMAGE);
    metaMask_.set(META_KEY_MEDIA_IMAGE_URI);
    title_ = "";
    artist_ = "";
    author_ = "";
    avQueueName_ = "";
    avQueueId_ = "";
    avQueueImage_ = nullptr;
    avQueueImageUri_ = "";
    bundleIcon_ = nullptr;
    album_ = "";
    writer_ = "";
    composer_ = "";
    duration_ = 0;
    publishDate_ = 0;
    subTitle_ = "";
    description_ = "";
    lyric_ = "";
    singleLyricText_ = "";
    previousAssetId_ = "";
    nextAssetId_ = "";
    skipIntervals_ = SECONDS_15;
    displayTags_ = 0;
    drmSchemes_.clear();
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
        SLOGD("assetId not equal here");
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

bool AVMetaData::EqualWithUri(const AVMetaData& metaData)
{
    if (metaData.mediaImage_ != nullptr) {
        SLOGI("Current fun cannot determine whether mediaImage_ is equal,\
            not perform subsequent judgments when mediaImage_ is not null.");
        return false;
    }

    return (assetId_ == metaData.assetId_)
        && (title_ == metaData.title_)
        && (artist_ == metaData.artist_)
        && (author_ == metaData.author_)
        && (avQueueName_ == metaData.avQueueName_)
        && (avQueueId_ == metaData.avQueueId_)
        && (avQueueImageUri_ == metaData.avQueueImageUri_)
        && (album_ == metaData.album_)
        && (writer_ == metaData.writer_)
        && (composer_ == metaData.composer_)
        && (duration_ == metaData.duration_)
        && (mediaImageUri_ == metaData.mediaImageUri_)
        && (publishDate_ == metaData.publishDate_)
        && (subTitle_ == metaData.subTitle_)
        && (description_ == metaData.description_)
        && (lyric_ == metaData.lyric_)
        && (singleLyricText_ == metaData.singleLyricText_)
        && (previousAssetId_ == metaData.previousAssetId_)
        && (nextAssetId_ == metaData.nextAssetId_)
        && (skipIntervals_ == metaData.skipIntervals_)
        && (filter_ == metaData.filter_)
        && (displayTags_ == metaData.displayTags_)
        && (drmSchemes_ == metaData.drmSchemes_);
}

bool AVMetaData::IsValid() const
{
    return duration_ >= AVMetaData::DURATION_ALWAYS_PLAY && publishDate_ >= 0
        && displayTags_ <= AVMetaData::DISPLAY_TAG_ALL;
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

void AVMetaData::CloneAVQueueName(const AVMetaData& from, AVMetaData& to)
{
    to.avQueueName_ = from.avQueueName_;
}

void AVMetaData::CloneAVQueueId(const AVMetaData& from, AVMetaData& to)
{
    to.avQueueId_ = from.avQueueId_;
}

void AVMetaData::CloneAVQueueImage(const AVMetaData& from, AVMetaData& to)
{
    to.avQueueImage_ = from.avQueueImage_;
}

void AVMetaData::CloneAVQueueImageUri(const AVMetaData& from, AVMetaData& to)
{
    to.avQueueImageUri_ = from.avQueueImageUri_;
}

void AVMetaData::CloneBundleIcon(const AVMetaData& from, AVMetaData& to)
{
    to.bundleIcon_ = from.bundleIcon_;
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

void AVMetaData::ClonePublishData(const AVMetaData& from, AVMetaData& to)
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

void AVMetaData::CloneSingleLyricText(const AVMetaData& from, AVMetaData& to)
{
    to.singleLyricText_ = from.singleLyricText_;
}

void AVMetaData::ClonePreviousAssetId(const AVMetaData& from, AVMetaData& to)
{
    to.previousAssetId_ = from.previousAssetId_;
}

void AVMetaData::CloneNextAssetId(const AVMetaData& from, AVMetaData& to)
{
    to.nextAssetId_ = from.nextAssetId_;
}

void AVMetaData::CloneSkipIntervals(const AVMetaData& from, AVMetaData& to)
{
    to.skipIntervals_ = from.skipIntervals_;
}

void AVMetaData::CloneFilter(const AVMetaData& from, AVMetaData& to)
{
    to.filter_ = from.filter_;
}

void AVMetaData::CloneDisplayTags(const AVMetaData& from, AVMetaData& to)
{
    to.displayTags_ = from.displayTags_;
}

void AVMetaData::CloneDrmSchemes(const AVMetaData& from, AVMetaData& to)
{
    to.drmSchemes_ = from.drmSchemes_;
}
} // namespace OHOS::AVSession
