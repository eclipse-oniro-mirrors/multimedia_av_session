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
        parcel.WriteString(avQueueName_) &&
        parcel.WriteString(avQueueId_) &&
        parcel.WriteString(avQueueImageUri_) &&
        parcel.WriteString(album_) &&
        parcel.WriteString(writer_) &&
        parcel.WriteString(composer_) &&
        parcel.WriteInt64(duration_) &&
        parcel.WriteString(mediaImageUri_) &&
        parcel.WriteDouble(publishDate_) &&
        parcel.WriteString(subTitle_) &&
        parcel.WriteString(description_) &&
        parcel.WriteString(lyric_) &&
        parcel.WriteString(singleLyricText_) &&
        parcel.WriteString(previousAssetId_) &&
        parcel.WriteString(nextAssetId_) &&
        parcel.WriteInt32(skipIntervals_) &&
        parcel.WriteInt32(filter_) &&
        parcel.WriteInt32(displayTags_) &&
        WriteDrmSchemes(parcel) &&
        parcel.WriteParcelable(mediaImage_.get()) &&
        parcel.WriteParcelable(avQueueImage_.get()) &&
        parcel.WriteParcelable(bundleIcon_.get());
}

AVMetaData *AVMetaData::Unmarshalling(Parcel& data)
{
    std::string mask;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(mask) && mask.length() == META_KEY_MAX, nullptr, "mask not valid");
    CHECK_AND_RETURN_RET_LOG(mask.find_first_not_of("01") == std::string::npos, nullptr, "mask string not 0 or 1");
    auto *result = new (std::nothrow) AVMetaData();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVMetaData failed");
    result->metaMask_ = MetaMaskType(mask);

    if (!UnmarshallingCheckParamTask(data, result)) {
        delete result;
        result = nullptr;
        return nullptr;
    }
    if (!UnmarshallingCheckImageTask(data, result)) {
        delete result;
        result = nullptr;
        return nullptr;
    }
    return result;
}

bool AVMetaData::UnmarshallingCheckParamTask(Parcel& data, AVMetaData *result)
{
    bool isParamUnsupport = (!data.ReadString(result->assetId_) ||
        !data.ReadString(result->title_) ||
        !data.ReadString(result->artist_) ||
        !data.ReadString(result->author_) ||
        !data.ReadString(result->avQueueName_) ||
        !data.ReadString(result->avQueueId_) ||
        !data.ReadString(result->avQueueImageUri_) ||
        !data.ReadString(result->album_) ||
        !data.ReadString(result->writer_) ||
        !data.ReadString(result->composer_) ||
        !data.ReadInt64(result->duration_) ||
        !data.ReadString(result->mediaImageUri_) ||
        !data.ReadDouble(result->publishDate_) ||
        !data.ReadString(result->subTitle_) ||
        !data.ReadString(result->description_) ||
        !data.ReadString(result->lyric_) ||
        !data.ReadString(result->singleLyricText_) ||
        !data.ReadString(result->previousAssetId_) ||
        !data.ReadString(result->nextAssetId_) ||
        !data.ReadInt32(result->skipIntervals_) ||
        !data.ReadInt32(result->filter_) ||
        !data.ReadInt32(result->displayTags_) ||
        !ReadDrmSchemes(data, result));
    if (isParamUnsupport)  {
        SLOGE("read AVMetaData failed");
        return false;
    }
    return true;
}

bool AVMetaData::UnmarshallingCheckImageTask(Parcel& data, AVMetaData *result)
{
    result->mediaImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->metaMask_.test(META_KEY_MEDIA_IMAGE) && result->mediaImage_ == nullptr) {
        SLOGE("read PixelMap failed");
        return false;
    }
    result->avQueueImage_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->metaMask_.test(META_KEY_AVQUEUE_IMAGE) && result->avQueueImage_ == nullptr) {
        SLOGE("read avqueue PixelMap failed");
        return false;
    }
    result->bundleIcon_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (result->metaMask_.test(META_KEY_BUNDLE_ICON) && result->bundleIcon_ == nullptr) {
        SLOGE("read bundle icon failed");
        return false;
    }
    return true;
}

bool AVMetaData::MarshallingExceptImg(MessageParcel& data, const AVMetaData metaIn)
{
    bool ret = data.WriteString(metaIn.metaMask_.to_string()) &&
        data.WriteString(metaIn.assetId_) &&
        data.WriteString(metaIn.title_) &&
        data.WriteString(metaIn.artist_) &&
        data.WriteString(metaIn.author_) &&
        data.WriteString(metaIn.avQueueName_) &&
        data.WriteString(metaIn.avQueueId_) &&
        data.WriteString(metaIn.avQueueImageUri_) &&
        data.WriteString(metaIn.album_) &&
        data.WriteString(metaIn.writer_) &&
        data.WriteString(metaIn.composer_) &&
        data.WriteInt64(metaIn.duration_) &&
        data.WriteString(metaIn.mediaImageUri_) &&
        data.WriteDouble(metaIn.publishDate_) &&
        data.WriteString(metaIn.subTitle_) &&
        data.WriteString(metaIn.description_) &&
        data.WriteString(metaIn.lyric_) &&
        data.WriteString(metaIn.singleLyricText_) &&
        data.WriteString(metaIn.previousAssetId_) &&
        data.WriteString(metaIn.nextAssetId_) &&
        data.WriteInt32(metaIn.skipIntervals_) &&
        data.WriteInt32(metaIn.filter_) &&
        data.WriteInt32(metaIn.mediaLength_) &&
        data.WriteInt32(metaIn.avQueueLength_) &&
        data.WriteInt32(metaIn.displayTags_) &&
        data.WriteParcelable(metaIn.bundleIcon_.get());
        WriteDrmSchemes(data, metaIn);
    SLOGD("MarshallingExceptImg without small img ret %{public}d", static_cast<int>(ret));
    return ret;
}

bool AVMetaData::UnmarshallingExceptImg(MessageParcel& data, AVMetaData& metaOut)
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
            metaOut.metaMask_.flip(maskSize - i - 1);
        }
    }

    bool ret = !data.ReadString(metaOut.assetId_) ||
        !data.ReadString(metaOut.title_) ||
        !data.ReadString(metaOut.artist_) ||
        !data.ReadString(metaOut.author_) ||
        !data.ReadString(metaOut.avQueueName_) ||
        !data.ReadString(metaOut.avQueueId_) ||
        !data.ReadString(metaOut.avQueueImageUri_) ||
        !data.ReadString(metaOut.album_) ||
        !data.ReadString(metaOut.writer_) ||
        !data.ReadString(metaOut.composer_) ||
        !data.ReadInt64(metaOut.duration_) ||
        !data.ReadString(metaOut.mediaImageUri_) ||
        !data.ReadDouble(metaOut.publishDate_) ||
        !data.ReadString(metaOut.subTitle_) ||
        !data.ReadString(metaOut.description_) ||
        !data.ReadString(metaOut.lyric_) ||
        !data.ReadString(metaOut.singleLyricText_) ||
        !data.ReadString(metaOut.previousAssetId_) ||
        !data.ReadString(metaOut.nextAssetId_) ||
        !data.ReadInt32(metaOut.skipIntervals_) ||
        !data.ReadInt32(metaOut.filter_) ||
        !data.ReadInt32(metaOut.mediaLength_) ||
        !data.ReadInt32(metaOut.avQueueLength_) ||
        !data.ReadInt32(metaOut.displayTags_);
    metaOut.bundleIcon_ = std::shared_ptr<AVSessionPixelMap>(data.ReadParcelable<AVSessionPixelMap>());
    if (metaOut.metaMask_.test(META_KEY_BUNDLE_ICON) && metaOut.bundleIcon_ == nullptr) {
        SLOGE("read bundle icon failed");
        return false;
    }
    ret = ret || !ReadDrmSchemes(data, metaOut);
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

bool AVMetaData::WriteDrmSchemes(MessageParcel& parcel, const AVMetaData metaData)
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(metaData.drmSchemes_.size()), false,
        "write drmSchemes size failed");
    for (auto drmScheme : metaData.drmSchemes_) {
        CHECK_AND_RETURN_RET_LOG(parcel.WriteString(drmScheme), false, "write drmScheme failed");
    }
    return true;
}

bool AVMetaData::ReadDrmSchemes(Parcel& parcel, AVMetaData *metaData)
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

bool AVMetaData::ReadDrmSchemes(MessageParcel& parcel, AVMetaData& metaData)
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
    metaData.drmSchemes_ = drmSchemes;
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

void AVMetaData::SetMediaLength(int32_t mediaLength)
{
    mediaLength_ = mediaLength;
}

int32_t AVMetaData::GetMediaLength() const
{
    return mediaLength_;
}

void AVMetaData::SetAVQueueLength(int32_t avQueueLength)
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

void AVMetaData::ResetExtAssetId()
{
    metaMask_.reset();
    metaMask_.set(META_KEY_ASSET_ID);
    title_ = "";
    artist_ = "";
    author_ = "";
    avQueueName_ = "";
    avQueueId_ = "";
    avQueueImage_ = nullptr;
    avQueueImageUri_ = "";
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
        SLOGE("assetId not equal here");
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
