/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_OHAVMEDIADESCRIPTION_H
#define OHOS_OHAVMEDIADESCRIPTION_H

#include <string>
#include "native_avqueueitem.h"
#include "pixelmap_native.h"
#include "pixelmap_native_impl.h"

namespace OHOS::AVSession {
class OHAVMediaDescription {
public:
    OHAVMediaDescription();
    ~OHAVMediaDescription();

    AVQueueItem_Result SetAssetId(const std::string& assetId);
    const std::string& GetAssetId() const;

    AVQueueItem_Result SetTitle(const std::string& title);
    const std::string& GetTitle() const;

    AVQueueItem_Result SetSubtitle(const std::string& subtitle);
    const std::string& GetSubtitle() const;

    AVQueueItem_Result SetArtist(const std::string& artist);
    const std::string& GetArtist() const;

    AVQueueItem_Result SetAlbumCoverUri(const std::string& albumCoverUri);
    const std::string& GetAlbumCoverUri() const;

    AVQueueItem_Result SetMediaType(const std::string& mediaType);
    const std::string& GetMediaType() const;

    AVQueueItem_Result SetLyricContent(const std::string& lyricContent);
    const std::string& GetLyricContent() const;

    AVQueueItem_Result SetDuration(int32_t duration);
    int32_t GetDuration() const;

    AVQueueItem_Result SetMediaUri(const std::string& mediaUri);
    const std::string& GetMediaUri() const;

    AVQueueItem_Result SetStartPosition(int32_t startPosition);
    int32_t GetStartPosition() const;

    AVQueueItem_Result SetMediaSize(int32_t mediaSize);
    int32_t GetMediaSize() const;

    AVQueueItem_Result SetAlbumTitle(const std::string& albumTitle);
    const std::string& GetAlbumTitle() const;

    AVQueueItem_Result SetAppName(const std::string& appName);
    const std::string& GetAppName() const;

private:
    std::string assetId_ = "";
    std::string mediaId_ = "";
    std::string title_ = "";
    std::string subtitle_ = "";
    std::string artist_ = "";
    std::string albumCoverUri_ = "";
    std::string mediaType_ = "";
    std::string lyricContent_ = "";
    int32_t duration_ = 0;
    std::string mediaUri_ = "";
    int32_t startPosition_ = 0;
    int32_t mediaSize_ = 0;
    std::string albumTitle_ = "";
    std::string appName_ = "";
};
}

#endif // OHOS_OHAVMEDIADESCRIPTION_H