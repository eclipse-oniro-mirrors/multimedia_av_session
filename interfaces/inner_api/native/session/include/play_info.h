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

#ifndef OHOS_PLAY_INFO_H
#define OHOS_PLAY_INFO_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avsession_pixel_map.h"
#include "want_params.h"

namespace OHOS::AVSession {
class PlayInfo : public Parcelable {
public:
    enum {
        PLAY_INFO_KEY_MEDIA_ID = 0,
        PLAY_INFO_KEY_MEDIA_NAME = 1,
        PLAY_INFO_KEY_MEDIA_URL = 2,
        PLAY_INFO_KEY_MEDIA_TYPE = 3,
        PLAY_INFO_KEY_START_POSITION = 4,
        PLAY_INFO_KEY_DURATION = 5,
        PLAY_INFO_KEY_ALBUM_COVER_URL = 6,
        PLAY_INFO_KEY_ALBUM_TITLE = 7,
        PLAY_INFO_KEY_ARTIST = 8,
        PLAY_INFO_KEY_LYRIC_URL = 9,
        PLAY_INFO_KEY_LYRIC_CONTENT = 10,
        PLAY_INFO_KEY_ICON = 11,
        PLAY_INFO_KEY_ICON_IMAGE = 12,
        PLAY_INFO_KEY_ICON_URL = 13,
        PLAY_INFO_KEY_APP_NAME = 14,
        PLAY_INFO_KEY_MAX = 15
    };

    PlayInfo() = default;
    
    ~PlayInfo() = default;

    static PlayInfo* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetMediaId(const std::string& mediaId);
    std::string GetMediaId() const;

    void SetMediaName(const std::string& mediaName);
    std::string GetMediaName() const;

    void SetMediaUrl(const std::string& mediaType);
    std::string GetMediaUrl() const;

    void SetMediaType(const std::string& mediaType);
    std::string GetMediaType() const;

    void SetStartPosition(const int32_t startPosition);
    int32_t GetStartPosition() const;

    void SetDuration(const int32_t duration);
    int32_t GetDuration() const;

    void SetAlbumCoverUrl(const std::string& albumCoverUrl);
    std::string GetAlbumCoverUrl() const;

    void SetAlbumTitle(const std::string& albumTitle);
    std::string GetAlbumTitle() const;

    void SetArtist(const std::string& artist);
    std::string GetArtist() const;

    void SetLyricUrl(const std::string& lyricUrl);
    std::string GetLyricUrl() const;

    void SetLyricContent(const std::string& lyricContent);
    std::string GetLyricContent() const;

    void SetIcon(const std::string& icon);
    std::string GetIcon() const;

    void SetIconImage(const std::shared_ptr<AVSessionPixelMap>& iconImage);
    std::shared_ptr<AVSessionPixelMap> GetIconImage() const;

    void SetIconUri(const std::string& iconUri);
    std::string GetIconUri() const;

    void SetAppName(const std::string& appName);
    std::string GetAppName() const;

    bool IsValid() const;

    void Reset();

private:
    std::string mediaId_ = "";
    std::string mediaName_ = "";
    std::string mediaUrl_ = "";
    std::string mediaType_ = "";
    int32_t startPosition_ = 0;
    int32_t duration_ = 0;
    std::string albumCoverUrl_ = "";
    std::string albumTitle_ = "";
    std::string artist_ = "";
    std::string lyricUrl_ = "";
    std::string lyricContent_ = "";
    std::string icon_ = "";
    std::shared_ptr<AVSessionPixelMap> iconImage_ = nullptr;
    std::string iconUri_ = "";
    std::string appName_ = "";
};
} // namespace OHOS::AVSession
#endif // OHOS_PLAY_INFO_H
