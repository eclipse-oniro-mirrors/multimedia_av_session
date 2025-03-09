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

#ifndef OHOS_AVMEDIA_DESCRIPTION_H
#define OHOS_AVMEDIA_DESCRIPTION_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avsession_pixel_map.h"
#include "want_params.h"
#include "av_file_descriptor.h"
#include "av_data_src_descriptor.h"

namespace OHOS::AVSession {
class AVMediaDescription : public Parcelable {
public:
    enum {
        MEDIA_DESCRIPTION_KEY_MEDIA_ID = 0,
        MEDIA_DESCRIPTION_KEY_TITLE = 1,
        MEDIA_DESCRIPTION_KEY_SUBTITLE = 2,
        MEDIA_DESCRIPTION_KEY_DESCRIPTION = 3,
        MEDIA_DESCRIPTION_KEY_ICON = 4,
        MEDIA_DESCRIPTION_KEY_ICON_URI = 5,
        MEDIA_DESCRIPTION_KEY_EXTRAS = 6,
        MEDIA_DESCRIPTION_KEY_MEDIA_TYPE = 7,
        MEDIA_DESCRIPTION_KEY_MEDIA_SIZE = 8,
        MEDIA_DESCRIPTION_KEY_ALBUM_TITLE = 9,
        MEDIA_DESCRIPTION_KEY_ALBUM_COVER_URI = 10,
        MEDIA_DESCRIPTION_KEY_LYRIC_CONTENT = 11,
        MEDIA_DESCRIPTION_KEY_LYRIC_URI = 12,
        MEDIA_DESCRIPTION_KEY_ARTIST = 13,
        MEDIA_DESCRIPTION_KEY_MEDIA_URI = 14,
        MEDIA_DESCRIPTION_KEY_FD_SRC = 15,
        MEDIA_DESCRIPTION_KEY_DURATION = 16,
        MEDIA_DESCRIPTION_KEY_START_POSITION = 17,
        MEDIA_DESCRIPTION_KEY_CREDITS_POSITION = 18,
        MEDIA_DESCRIPTION_KEY_APP_NAME = 19,
        MEDIA_DESCRIPTION_KEY_DRM_SCHEME = 20,
        MEDIA_DESCRIPTION_KEY_DATA_SRC = 21,
        MEDIA_DESCRIPTION_KEY_MAX = 22,
    };

    AVMediaDescription() = default;
    
    ~AVMediaDescription() = default;

    static AVMediaDescription* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetMediaId(const std::string& mediaId);
    std::string GetMediaId() const;

    void SetTitle(const std::string& title);
    std::string GetTitle() const;

    void SetSubtitle(const std::string& subtitle);
    std::string GetSubtitle() const;

    void SetDescription(const std::string& description);
    std::string GetDescription() const;

    void SetIcon(const std::shared_ptr<AVSessionPixelMap>& icon);
    std::shared_ptr<AVSessionPixelMap> GetIcon() const;

    void SetIconUri(const std::string& iconUri);
    std::string GetIconUri() const;

    void SetExtras(const std::shared_ptr<AAFwk::WantParams>& extras);
    std::shared_ptr<AAFwk::WantParams> GetExtras() const;

    void SetMediaType(const std::string& mediaType);
    std::string GetMediaType() const;

    void SetMediaSize(const int32_t mediaSize);
    int32_t GetMediaSize() const;

    void SetAlbumTitle(const std::string& albumTitle);
    std::string GetAlbumTitle() const;

    void SetAlbumCoverUri(const std::string& albumCoverUri);
    std::string GetAlbumCoverUri() const;

    void SetLyricContent(const std::string& lyricContent);
    std::string GetLyricContent() const;

    void SetLyricUri(const std::string& lyricUri);
    std::string GetLyricUri() const;

    void SetArtist(const std::string& artist);
    std::string GetArtist() const;

    void SetMediaUri(const std::string& mediaUri);
    std::string GetMediaUri() const;

    void SetFdSrc(const AVFileDescriptor& fdSrc);
    AVFileDescriptor GetFdSrc() const;

    void SetDuration(const int32_t duration);
    int32_t GetDuration() const;

    void SetStartPosition(const int32_t startPosition);
    int32_t GetStartPosition() const;

    void SetCreditsPosition(const int32_t creditsPosition);
    int32_t GetCreditsPosition() const;

    void SetAppName(const std::string& appName);
    std::string GetAppName() const;

    void SetDrmScheme(const std::string& drmScheme);
    std::string GetDrmScheme() const;

    void SetDataSrc(const AVDataSrcDescriptor& fdSrc);
    AVDataSrcDescriptor GetDataSrc() const;

    bool IsValid() const;

    void Reset();

private:
    std::string mediaId_ = "";
    std::string title_ = "";
    std::string subtitle_ = "";
    std::string description_ = "";
    std::shared_ptr<AVSessionPixelMap> icon_ = nullptr;
    std::string iconUri_ = "";
    std::shared_ptr<AAFwk::WantParams> extras_ = nullptr;
    std::string mediaType_ = "";
    int32_t mediaSize_ = 0;
    std::string albumTitle_ = "";
    std::string albumCoverUri_ = "";
    std::string lyricContent_ = "";
    std::string lyricUri_ = "";
    std::string artist_ = "";
    std::string mediaUri_ = "";
    AVFileDescriptor fdSrc_;
    int32_t duration_ = 0;
    int32_t startPosition_ = 0;
    int32_t creditsPosition_ = 0;
    std::string appName_ = "";
    std::string drmScheme_ = "";
    AVDataSrcDescriptor dataSrc_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVMEDIA_DESCRIPTION_H

