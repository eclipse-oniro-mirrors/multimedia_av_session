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
#ifndef OHOS_AVSESSION_METADATA_H
#define OHOS_AVSESSION_METADATA_H

#include <bitset>
#include <memory>
#include <string>

#include "parcel.h"
#include "pixel_map.h"

namespace OHOS::AVSession {
class AVMetaData : public Parcelable {
public:
    enum {
        META_KEY_MEDIA_ID,
        META_KEY_TITLE,
        META_KEY_ARTIST,
        META_KEY_AUTHOR,
        META_KEY_ALBUM,
        META_KEY_WRITER,
        META_KEY_COMPOSER,
        META_KEY_DURATION,
        META_KEY_MEDIA_IMAGE,
        META_KEY_MEDIA_IMAGE_URI,
        META_KEY_APP_ICON,
        META_KEY_APP_ICON_URI,
        META_KEY_PUBLISH_DATA,
        META_KEY_SUBTITLE,
        META_KEY_DESCRIPTION,
        META_KEY_LYRIC,
        META_KEY_MAX
    };

    using MetaMaskType = std::bitset<META_KEY_MAX>;

    AVMetaData();

    static AVMetaData *Unmarshalling(Parcel& parcel);

    bool Marshalling(Parcel& parcel) const override;

    void SetMediaId(const std::string& mediaId);

    std::string GetMediaId() const ;

    void SetTitle(const std::string& title);

    std::string GetTitle() const;

    void SetArtist(const std::string& artist);

    std::string GetArtist() const;

    void SetAuthor(const std::string& author);

    std::string GetAuthor() const;

    void SetAlbum(const std::string& album);

    std::string GetAlbum() const;

    void SetWriter(const std::string& wrtier);

    std::string GetWriter() const;

    void SetComposer(const std::string& composer);

    std::string GetComposer() const;

    void SetDuration(int64_t duration);

    int64_t GetDuration() const;

    void SetMediaImage(const std::shared_ptr<Media::PixelMap>& mediaImage);

    std::shared_ptr<Media::PixelMap> GetMediaImage() const;

    void SetMediaImageUri(const std::string& mediaImageUri);

    std::string GetMediaImageUri() const;

    void SetAppIcon(const std::shared_ptr<Media::PixelMap>& appIcon);

    std::shared_ptr<Media::PixelMap> GetAppIcon() const;

    void SetAppIconUri(const std::string& appIconUri);

    std::string GetAppIconUri() const;

    void SetSubTitle(const std::string& subTitle);

    std::string GetSubTitle() const;

    void SetDescription(const std::string& description);

    std::string GetDescription() const;

    void SetLyric(const std::string& lyric);

    std::string GetLyric() const;

    void Reset();

    void SetMetaMask(const MetaMaskType metaMask);

    MetaMaskType GetMetaMask() const;

    /*
     * copy meta item to @metaOut according to intersection of meta mask.
     * @return true if intersection is not empty, else return false.
     */
    bool CopyToByMask(AVMetaData& metaOut) const;

    /*
     * copy meta item from @metaIn according to set bit of @metaIn meta mask, keeping other meta item of self
     * not changed, when both mediaId is equal. Otherwise, just do object assignment.
     * @return true if this meta changed.
     */
    bool CopyFrom(const AVMetaData& metaIn);

private:
    MetaMaskType metaMask_;

    std::string mediaId_;
    std::string title_;
    std::string artist_;
    std::string author_;
    std::string album_;
    std::string writer_;
    std::string composer_;
    int64_t duration_ = 0;
    std::shared_ptr<Media::PixelMap> mediaImage_;
    std::string mediaImageUri_;
    std::shared_ptr<Media::PixelMap> appIcon_;
    std::string appIconUri_;
    std::string subTitle_;
    std::string description_;
    std::string lyric_;

    static void CloneMediaId(const AVMetaData& from, AVMetaData& to);
    static void CloneTitile(const AVMetaData& from, AVMetaData& to);
    static void CloneArtist(const AVMetaData& from, AVMetaData& to);
    static void CloneAuthor(const AVMetaData& from, AVMetaData& to);
    static void CloneAlbum(const AVMetaData& from, AVMetaData& to);
    static void CloneWriter(const AVMetaData& from, AVMetaData& to);
    static void CloneComposer(const AVMetaData& from, AVMetaData& to);
    static void CloneDuration(const AVMetaData& from, AVMetaData& to);
    static void CloneMediaImage(const AVMetaData& from, AVMetaData& to);
    static void CloneMediaImageUri(const AVMetaData& from, AVMetaData& to);
    static void CloneAppIcon(const AVMetaData& from, AVMetaData& to);
    static void CloneAppIconUri(const AVMetaData& from, AVMetaData& to);
    static void CloneSubTitile(const AVMetaData& from, AVMetaData& to);
    static void CloneDescriptiion(const AVMetaData& from, AVMetaData& to);
    static void CloneLyric(const AVMetaData& from, AVMetaData& to);

    using CloneActionType = void(*)(const AVMetaData& from, AVMetaData& to);
    static inline CloneActionType cloneActions[META_KEY_MAX] = {
        [META_KEY_MEDIA_ID] = &AVMetaData::CloneMediaId,
        [META_KEY_TITLE] = &AVMetaData::CloneTitile,
        [META_KEY_ARTIST] = &AVMetaData::CloneArtist,
        [META_KEY_AUTHOR] = &AVMetaData::CloneAuthor,
        [META_KEY_ALBUM] = &AVMetaData::CloneAlbum,
        [META_KEY_WRITER] = &AVMetaData::CloneWriter,
        [META_KEY_COMPOSER] = &AVMetaData::CloneComposer,
        [META_KEY_DURATION] = &AVMetaData::CloneDuration,
        [META_KEY_MEDIA_IMAGE] = &AVMetaData::CloneMediaImage,
        [META_KEY_MEDIA_IMAGE_URI] = &AVMetaData::CloneMediaImageUri,
        [META_KEY_APP_ICON] = &AVMetaData::CloneAppIcon,
        [META_KEY_APP_ICON_URI] = &AVMetaData::CloneAppIconUri,
        [META_KEY_SUBTITLE] = &AVMetaData::CloneSubTitile,
        [META_KEY_DESCRIPTION] = &AVMetaData::CloneDescriptiion,
        [META_KEY_LYRIC] = &AVMetaData::CloneLyric,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_METADATA_H