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
#ifndef OHOS_AVMETA_DATA_H
#define OHOS_AVMETA_DATA_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "iremote_proxy.h"
#include "parcel.h"
#include "avsession_pixel_map.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
class AVMetaData : public Parcelable {
public:
    static constexpr std::int64_t DURATION_ALWAYS_PLAY = -1;
    enum {
        META_KEY_ASSET_ID = 0,
        META_KEY_TITLE = 1,
        META_KEY_ARTIST = 2,
        META_KEY_AUTHOR = 3,
        META_KEY_AVQUEUE_NAME = 4,
        META_KEY_AVQUEUE_ID = 5,
        META_KEY_AVQUEUE_IMAGE = 6,
        META_KEY_AVQUEUE_IMAGE_URI = 7,
        META_KEY_ALBUM = 8,
        META_KEY_WRITER = 9,
        META_KEY_COMPOSER = 10,
        META_KEY_DURATION = 11,
        META_KEY_MEDIA_IMAGE = 12,
        META_KEY_MEDIA_IMAGE_URI = 13,
        META_KEY_PUBLISH_DATE = 14,
        META_KEY_SUBTITLE = 15,
        META_KEY_DESCRIPTION = 16,
        META_KEY_LYRIC = 17,
        META_KEY_PREVIOUS_ASSET_ID = 18,
        META_KEY_NEXT_ASSET_ID = 19,
        META_KEY_SKIP_INTERVALS = 20,
        META_KEY_FILTER = 21,
        META_KEY_DISPLAY_TAGS = 22,
        META_KEY_DRM_SCHEMES = 23,
        META_KEY_BUNDLE_ICON = 24,
        META_KEY_SINGLE_LYRIC_TEXT = 25,
        META_KEY_MAX = 26
    };

    enum {
        SECONDS_10 = 10,
        SECONDS_15 = 15,
        SECONDS_30 = 30
    };

    enum {
        DISPLAY_TAG_AUDIO_VIVID = 1,
        // indicate all supported sound source for gold flag, you should make OR operation if add new options
        DISPLAY_TAG_ALL = DISPLAY_TAG_AUDIO_VIVID
    };

    using MetaMaskType = std::bitset<META_KEY_MAX>;

    AVMetaData() = default;
    ~AVMetaData() = default;

    static AVMetaData* Unmarshalling(Parcel& in);
    bool ReadFromParcel(MessageParcel& in, int32_t twoImageLength);
    bool Marshalling(Parcel& parcel) const override;
    bool WriteToParcel(MessageParcel& parcel) const;

    bool UnmarshallingExceptImg(MessageParcel& data);
    bool MarshallingExceptImg(MessageParcel& data) const;

    bool WriteDrmSchemes(Parcel& parcel) const;
    bool WriteDrmSchemes(MessageParcel& parcel);
    bool ReadDrmSchemes(MessageParcel& parcel);
    static bool ReadDrmSchemes(Parcel& parcel, AVMetaData *metaData);

    void SetAssetId(const std::string& assetId);
    std::string GetAssetId() const;

    void SetTitle(const std::string& title);
    std::string GetTitle() const;

    void SetArtist(const std::string& artist);
    std::string GetArtist() const;

    void SetAuthor(const std::string& author);
    std::string GetAuthor() const;

    void SetAVQueueName(const std::string& avQueueName);
    std::string GetAVQueueName() const;
  
    void SetAVQueueId(const std::string& avQueueId);
    std::string GetAVQueueId() const;
  
    void SetAVQueueImage(const std::shared_ptr<AVSessionPixelMap>& avQueueImage);
    std::shared_ptr<AVSessionPixelMap> GetAVQueueImage() const;
  
    void SetAVQueueImageUri(const std::string& avQueueImageUri);
    std::string GetAVQueueImageUri() const;

    void SetBundleIcon(const std::shared_ptr<AVSessionPixelMap>& avQueueImage);
    std::shared_ptr<AVSessionPixelMap> GetBundleIcon() const;

    void SetAlbum(const std::string& album);
    std::string GetAlbum() const;

    void SetWriter(const std::string& writer);
    std::string GetWriter() const;

    void SetComposer(const std::string& composer);
    std::string GetComposer() const;

    void SetDuration(int64_t duration);
    int64_t GetDuration() const;

    void SetMediaImage(const std::shared_ptr<AVSessionPixelMap>& mediaImage);
    std::shared_ptr<AVSessionPixelMap> GetMediaImage() const;

    void SetMediaImageUri(const std::string& mediaImageUri);
    std::string GetMediaImageUri() const;

    void SetPublishDate(double date);
    double GetPublishDate() const;

    void SetSubTitle(const std::string& subTitle);
    std::string GetSubTitle() const;

    void SetDescription(const std::string& description);
    std::string GetDescription() const;

    void SetLyric(const std::string& lyric);
    std::string GetLyric() const;

    void SetSingleLyricText(const std::string& singleLyricText);
    std::string GetSingleLyricText() const;

    void SetPreviousAssetId(const std::string& assetId);
    std::string GetPreviousAssetId() const;

    void SetNextAssetId(const std::string& assetId);
    std::string GetNextAssetId() const;

    void SetSkipIntervals(int32_t assetId);
    int32_t GetSkipIntervals() const;

    void SetFilter(int32_t filter);
    int32_t GetFilter() const;
    
    void SetMediaLength(int32_t mediaLength) const;
    int32_t GetMediaLength() const;

    void SetAVQueueLength(int32_t avQueueLength) const;
    int32_t GetAVQueueLength() const;

    void SetDisplayTags(int32_t displayTags);
    int32_t GetDisplayTags() const;

    void SetDrmSchemes(std::vector<std::string> drmSchemes);
    std::vector<std::string> GetDrmSchemes() const;

    void Reset();
    void ResetToBaseMeta();

    MetaMaskType GetMetaMask() const;

    bool CopyToByMask(MetaMaskType& mask, AVMetaData& metaOut) const;

    MetaMaskType GetChangedDataMask(const MetaMaskType& filter, const AVMetaData& newData) const;

    bool CopyFrom(const AVMetaData& metaIn);

    bool EqualWithUri(const AVMetaData& metaData);

    bool IsValid() const;

    int GetMediaImageTopic() const;

    const static inline std::vector<int32_t> localCapability {
        META_KEY_ASSET_ID,
        META_KEY_TITLE,
        META_KEY_ARTIST,
        META_KEY_AUTHOR,
        META_KEY_AVQUEUE_NAME,
        META_KEY_AVQUEUE_ID,
        META_KEY_AVQUEUE_IMAGE,
        META_KEY_AVQUEUE_IMAGE_URI,
        META_KEY_ALBUM,
        META_KEY_WRITER,
        META_KEY_COMPOSER,
        META_KEY_DURATION,
        META_KEY_MEDIA_IMAGE,
        META_KEY_MEDIA_IMAGE_URI,
        META_KEY_PUBLISH_DATE,
        META_KEY_SUBTITLE,
        META_KEY_DESCRIPTION,
        META_KEY_LYRIC,
        META_KEY_PREVIOUS_ASSET_ID,
        META_KEY_NEXT_ASSET_ID,
        META_KEY_SKIP_INTERVALS,
        META_KEY_FILTER,
        META_KEY_DISPLAY_TAGS,
        META_KEY_DRM_SCHEMES,
        META_KEY_BUNDLE_ICON,
        META_KEY_SINGLE_LYRIC_TEXT
    };

private:
    MetaMaskType metaMask_;

    std::string assetId_ = "";
    std::string title_ = "";
    std::string artist_ = "";
    std::string author_ = "";
    std::string avQueueName_ = "";
    std::string avQueueId_ = "";
    std::shared_ptr<AVSessionPixelMap> avQueueImage_ = nullptr;
    std::string avQueueImageUri_ = "";
    std::string album_ = "";
    std::string writer_ = "";
    std::string composer_ = "";
    int64_t duration_ = 0;
    std::shared_ptr<AVSessionPixelMap> mediaImage_ = nullptr;
    std::string mediaImageUri_ = "";
    double publishDate_ = 0;
    std::string subTitle_ = "";
    std::string description_ = "";
    std::string lyric_ = "";
    std::string previousAssetId_ = "";
    std::string nextAssetId_ = "";
    int32_t skipIntervals_ = SECONDS_15;
    int32_t filter_ = 2;
    mutable int32_t mediaLength_ = 0;
    mutable int32_t avQueueLength_ = 0;
    int32_t displayTags_ = 0;
    std::vector<std::string> drmSchemes_;
    std::shared_ptr<AVSessionPixelMap> bundleIcon_ = nullptr;
    std::string singleLyricText_ = "";

    static bool CheckAssetIdChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckTitleChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckArtistChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAuthorChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAVQueueNameChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAVQueueIdChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAVQueueImageChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAVQueueImageUriChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckAlbumChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckWriterChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckComposerChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckDurationChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckMediaImageChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckMediaImageUriChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckPublishDataChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckSubTitleChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckDescriptionChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckLyricChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckPreviousAssetIdChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckNextAssetIdChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckSkipIntervalsChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckFilterChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckDisplayTagsChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckDrmSchemesChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckBundleIconChange(const AVMetaData& from, const AVMetaData& to);
    static bool CheckSingleLyricTextChange(const AVMetaData& from, const AVMetaData& to);
    using CheckActionType = bool(*)(const AVMetaData& from, const AVMetaData& to);
    static inline CheckActionType checkActions[META_KEY_MAX] = {
        &AVMetaData::CheckAssetIdChange,
        &AVMetaData::CheckTitleChange,
        &AVMetaData::CheckArtistChange,
        &AVMetaData::CheckAuthorChange,
        &AVMetaData::CheckAVQueueNameChange,
        &AVMetaData::CheckAVQueueIdChange,
        &AVMetaData::CheckAVQueueImageChange,
        &AVMetaData::CheckAVQueueImageUriChange,
        &AVMetaData::CheckAlbumChange,
        &AVMetaData::CheckWriterChange,
        &AVMetaData::CheckComposerChange,
        &AVMetaData::CheckDurationChange,
        &AVMetaData::CheckMediaImageChange,
        &AVMetaData::CheckMediaImageUriChange,
        &AVMetaData::CheckPublishDataChange,
        &AVMetaData::CheckSubTitleChange,
        &AVMetaData::CheckDescriptionChange,
        &AVMetaData::CheckLyricChange,
        &AVMetaData::CheckPreviousAssetIdChange,
        &AVMetaData::CheckNextAssetIdChange,
        &AVMetaData::CheckSkipIntervalsChange,
        &AVMetaData::CheckFilterChange,
        &AVMetaData::CheckDisplayTagsChange,
        &AVMetaData::CheckDrmSchemesChange,
        &AVMetaData::CheckBundleIconChange,
        &AVMetaData::CheckSingleLyricTextChange
    };

    static void CloneAssetId(const AVMetaData& from, AVMetaData& to);
    static void CloneTitle(const AVMetaData& from, AVMetaData& to);
    static void CloneArtist(const AVMetaData& from, AVMetaData& to);
    static void CloneAuthor(const AVMetaData& from, AVMetaData& to);
    static void CloneAVQueueName(const AVMetaData& from, AVMetaData& to);
    static void CloneAVQueueId(const AVMetaData& from, AVMetaData& to);
    static void CloneAVQueueImage(const AVMetaData& from, AVMetaData& to);
    static void CloneAVQueueImageUri(const AVMetaData& from, AVMetaData& to);
    static void CloneAlbum(const AVMetaData& from, AVMetaData& to);
    static void CloneWriter(const AVMetaData& from, AVMetaData& to);
    static void CloneComposer(const AVMetaData& from, AVMetaData& to);
    static void CloneDuration(const AVMetaData& from, AVMetaData& to);
    static void CloneMediaImage(const AVMetaData& from, AVMetaData& to);
    static void CloneMediaImageUri(const AVMetaData& from, AVMetaData& to);
    static void ClonePublishData(const AVMetaData& from, AVMetaData& to);
    static void CloneSubTitle(const AVMetaData& from, AVMetaData& to);
    static void CloneDescription(const AVMetaData& from, AVMetaData& to);
    static void CloneLyric(const AVMetaData& from, AVMetaData& to);
    static void ClonePreviousAssetId(const AVMetaData& from, AVMetaData& to);
    static void CloneNextAssetId(const AVMetaData& from, AVMetaData& to);
    static void CloneSkipIntervals(const AVMetaData& from, AVMetaData& to);
    static void CloneFilter(const AVMetaData& from, AVMetaData& to);
    static void CloneDisplayTags(const AVMetaData& from, AVMetaData& to);
    static void CloneDrmSchemes(const AVMetaData& from, AVMetaData& to);
    static void CloneBundleIcon(const AVMetaData& from, AVMetaData& to);
    static void CloneSingleLyricText(const AVMetaData& from, AVMetaData& to);

    using CloneActionType = void(*)(const AVMetaData& from, AVMetaData& to);
    static inline CloneActionType cloneActions[META_KEY_MAX] = {
        &AVMetaData::CloneAssetId,
        &AVMetaData::CloneTitle,
        &AVMetaData::CloneArtist,
        &AVMetaData::CloneAuthor,
        &AVMetaData::CloneAVQueueName,
        &AVMetaData::CloneAVQueueId,
        &AVMetaData::CloneAVQueueImage,
        &AVMetaData::CloneAVQueueImageUri,
        &AVMetaData::CloneAlbum,
        &AVMetaData::CloneWriter,
        &AVMetaData::CloneComposer,
        &AVMetaData::CloneDuration,
        &AVMetaData::CloneMediaImage,
        &AVMetaData::CloneMediaImageUri,
        &AVMetaData::ClonePublishData,
        &AVMetaData::CloneSubTitle,
        &AVMetaData::CloneDescription,
        &AVMetaData::CloneLyric,
        &AVMetaData::ClonePreviousAssetId,
        &AVMetaData::CloneNextAssetId,
        &AVMetaData::CloneSkipIntervals,
        &AVMetaData::CloneFilter,
        &AVMetaData::CloneDisplayTags,
        &AVMetaData::CloneDrmSchemes,
        &AVMetaData::CloneBundleIcon,
        &AVMetaData::CloneSingleLyricText
    };

    int8_t minImgSize_ = 2;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVMETA_DATA_H