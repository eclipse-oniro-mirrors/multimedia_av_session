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
#ifndef OHOS_OHAVSESSION_DESCRIPTION_BUILDER_H
#define OHOS_OHAVSESSION_DESCRIPTION_BUILDER_H

#include <string>
#include "native_avqueueitem.h"
#include "pixelmap_native.h"
#include "OHAVMediaDescription.h"

namespace OHOS::AVSession {
class OHAVMediaDescriptionBuilder {
public:
    AVQueueItem_Result SetAssetId(const std::string& assetId);

    AVQueueItem_Result SetTitle(const std::string& title);

    AVQueueItem_Result SetSubtitle(const std::string& subtitle);

    AVQueueItem_Result SetArtist(const std::string& artist);

    AVQueueItem_Result SetMediaImage(OH_PixelmapNative *mediaImage);

    AVQueueItem_Result SetMediaType(const std::string& mediaType);

    AVQueueItem_Result SetLyricContent(const std::string& lyricContent);

    AVQueueItem_Result SetDuration(int32_t duration);

    AVQueueItem_Result SetMediaUri(const std::string& mediaUri);

    AVQueueItem_Result SetStartPosition(int32_t startPosition);

    AVQueueItem_Result SetMediaSize(int32_t mediaSize);

    AVQueueItem_Result SetAlbumTitle(const std::string& albumTitle);

    AVQueueItem_Result SetAppName(const std::string& appName);

    AVQueueItem_Result GenerateAVMediaDescription(OHAVMediaDescription** avMediaDescription);

private:
    std::string assetId_ = "";
    std::string mediaId_ = "";
    std::string title_ = "";
    std::string subtitle_ = "";
    std::string artist_ = "";
    OH_PixelmapNative *mediaImage_ = nullptr;
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

#endif // OHOS_OHAVSESSION_DESCRIPTION_BUILDER_H