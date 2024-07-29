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

#ifndef OHOS_NAPI_MEDIA_DESCRIPTION_H
#define OHOS_NAPI_MEDIA_DESCRIPTION_H

#include "avmedia_description.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiMediaDescription {
public:
    static napi_status GetValue(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetValue(napi_env env, const AVMediaDescription& in, napi_value& out);

    using GetterType = std::function<napi_status(napi_env, napi_value in, AVMediaDescription& out)>;
    using SetterType = std::function<napi_status(napi_env env, const AVMediaDescription& in, napi_value& out)>;

private:
    static napi_status GetMediaId(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetMediaId(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetAssetId(napi_env env, napi_value in, AVMediaDescription& out);

    static napi_status GetTitle(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetTitle(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetSubtitle(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetSubtitle(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetDescription(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetDescription(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetIcon(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetIcon(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetIconUri(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetIconUri(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetMediaImage(napi_env env, napi_value in, AVMediaDescription& out);

    static napi_status GetExtras(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetExtras(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetMediaType(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetMediaType(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetMediaSize(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetMediaSize(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetAlbumTitle(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetAlbumTitle(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetAlbumCoverUri(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetAlbumCoverUri(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetLyricContent(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetLyricContent(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetLyricUri(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetLyricUri(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetArtist(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetArtist(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetMediaUri(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetMediaUri(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetFdSrc(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetFdSrc(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetDuration(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetDuration(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetStartPosition(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetStartPosition(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetCreditsPosition(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetCreditsPosition(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetAppName(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetAppName(napi_env env, const AVMediaDescription& in, napi_value& out);

    static napi_status GetDrmScheme(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetDrmScheme(napi_env env, const AVMediaDescription& in, napi_value& out);

    static void CheckAndSetDefaultString(napi_status status, std::string& defaultStr);
    static void CheckAndSetDefaultInt(napi_status status, int32_t& defaultInt);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;

    static constexpr int GETTER_INDEX = 0;
    static constexpr int SETTER_INDEX = 1;
    static constexpr int ENUM_INDEX = 2;
};
}
#endif // OHOS_NAPI_MEDIA_DESCRIPTION_H
