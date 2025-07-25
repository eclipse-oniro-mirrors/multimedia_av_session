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

#ifndef TAIHE_MEDIA_DESCRIPTION_H
#define TAIHE_MEDIA_DESCRIPTION_H

#include "avmedia_description.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheMediaDescription {
public:
    static int32_t GetAVMediaDescription(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetAVMediaDescription(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);
    static AVMediaDescription CreateUndefinedAVMediaDescription();

    using GetterType = std::function<int32_t(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)>;

private:
    static void CheckAndSetDefaultString(int32_t status, std::string &defaultStr);

    static int32_t GetAssetId(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetAssetId(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetTitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetTitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetSubtitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetSubtitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetDescription(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetDescription(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetMediaImage(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetMediaImage(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);
    static int32_t SetMediaImageUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetExtras(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetExtras(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetMediaType(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetMediaType(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetMediaSize(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetMediaSize(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetAlbumTitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetAlbumTitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetAlbumCoverUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetAlbumCoverUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetLyricContent(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetLyricContent(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetLyricUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetLyricUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetArtist(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetArtist(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetMediaUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetMediaUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetFdSrc(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetFdSrc(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetDataSrc(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetDataSrc(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetPcmSrc(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetPcmSrc(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetDrmScheme(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetDrmScheme(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetDuration(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetDuration(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetStartPosition(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetStartPosition(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetCreditsPosition(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetCreditsPosition(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static int32_t GetAppName(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out);
    static int32_t SetAppName(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;

    static constexpr int32_t DEFAULT_INT32_VALUE = -1;
};
} // namespace ANI::AVSession
#endif // TAIHE_MEDIA_DESCRIPTION_H