/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "napi_media_description.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiMediaDescription::GetterType> NapiMediaDescription::getterMap_ = {
    { "mediaId", GetMediaId },
    { "assetId", GetAssetId },
    { "title", GetTitle },
    { "subtitle", GetSubtitle },
    { "description", GetDescription },
    { "icon",  GetIcon },
    { "iconUri", GetIconUri },
    { "mediaImage", GetMediaImage },
    { "extras", GetExtras },
    { "mediaType", GetMediaType },
    { "mediaSize", GetMediaSize },
    { "albumTitle", GetAlbumTitle },
    { "albumCoverUri", GetAlbumCoverUri },
    { "lyricContent", GetLyricContent },
    { "lyricUri", GetLyricUri },
    { "artist", GetArtist },
    { "mediaUri", GetMediaUri },
    { "fdSrc", GetFdSrc },
    { "duration", GetDuration },
    { "startPosition", GetStartPosition },
    { "creditsPosition", GetCreditsPosition },
    { "appName", GetAppName },
    { "drmScheme", GetDrmScheme },
    { "dataSrc", GetDataSrc },
    { "pcmSrc", GetPcmSrc },
    { "launchClientData", GetLaunchClientData },
};

std::map<int32_t, NapiMediaDescription::SetterType> NapiMediaDescription::setterMap_ = {
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_ID, SetMediaId },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_TITLE, SetTitle },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_SUBTITLE, SetSubtitle },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_DESCRIPTION, SetDescription },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_ICON,  SetIcon },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_ICON_URI, SetIconUri },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_EXTRAS, SetExtras },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_TYPE, SetMediaType },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_SIZE, SetMediaSize },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_ALBUM_TITLE, SetAlbumTitle },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_ALBUM_COVER_URI, SetAlbumCoverUri },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_LYRIC_CONTENT, SetLyricContent },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_LYRIC_URI, SetLyricUri },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_ARTIST, SetArtist },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_URI, SetMediaUri },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_FD_SRC, SetFdSrc },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_DURATION, SetDuration },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_START_POSITION, SetStartPosition },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_CREDITS_POSITION, SetCreditsPosition },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_APP_NAME, SetAppName },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_DRM_SCHEME, SetDrmScheme },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_DATA_SRC, SetDataSrc },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_PCM_SRC, SetPcmSrc },
    { AVMediaDescription::MEDIA_DESCRIPTION_KEY_LAUNCH_CLIENT_DATA, SetLaunchClientData },
};

napi_status NapiMediaDescription::GetValue(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGW("property %{public}s is not of mediadescription", name.c_str());
            continue;
        }
        auto getter = it->second;
        if (getter(env, in, out) != napi_ok) {
            SLOGE("get property %{public}s failed", name.c_str());
            return napi_generic_failure;
        }
    }

    return napi_ok;
}

napi_status NapiMediaDescription::SetValue(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < AVMediaDescription::MEDIA_DESCRIPTION_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

void NapiMediaDescription::CheckAndSetDefaultString(napi_status status, std::string& defaultStr)
{
    if (status != napi_ok) {
        SLOGW("Get value from napi_value failed, use default value");
        defaultStr = "";
    }
}

void NapiMediaDescription::CheckAndSetDefaultInt(napi_status status, int32_t& defaultInt)
{
    if (status != napi_ok) {
        SLOGW("Get value from napi_value failed, use default value");
        defaultInt = -1;
    }
}

napi_status NapiMediaDescription::GetMediaId(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaId", property);
    if (status != napi_ok) {
        status = NapiUtils::GetNamedProperty(env, in, "assetId", property);
        CHECK_RETURN(status == napi_ok, "get property failed", status);
    }
    out.SetMediaId(property);
    return status;
}

napi_status NapiMediaDescription::SetMediaId(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "set property mediaId failed", status);
    status = napi_set_named_property(env, out, "assetId", property);
    CHECK_RETURN(status == napi_ok, "set property assetId failed", status);
    return status;
}

napi_status NapiMediaDescription::GetAssetId(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get assetId");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "assetId", property);
    if (status == napi_ok) {
        SLOGI("MediaDescription has assetId");
        out.SetMediaId(property);
    }
    return status;
}

napi_status NapiMediaDescription::GetTitle(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "title", property);
    CheckAndSetDefaultString(status, property);
    out.SetTitle(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetTitle(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "title", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetSubtitle(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "subtitle", property);
    CheckAndSetDefaultString(status, property);
    out.SetSubtitle(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetSubtitle(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetSubtitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "subtitle", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetDescription(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "description", property);
    CheckAndSetDefaultString(status, property);
    out.SetDescription(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetDescription(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDescription(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "description", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetIcon(napi_env env, napi_value in, AVMediaDescription& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "icon", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property icon failed", napi_ok);
    auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
    if (pixelMap == nullptr) {
        SLOGE("unwrap failed");
        return napi_invalid_arg;
    }
    out.SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
    return status;
}

napi_status NapiMediaDescription::SetIcon(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    auto pixelMap = in.GetIcon();
    if (pixelMap == nullptr) {
        SLOGI("media image is null");
        return napi_ok;
    }
    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "icon", property);
    if (status != napi_ok) {
        SLOGW("check icon with no property");
    }
    status = napi_set_named_property(env, out, "mediaImage", property);
    if (status != napi_ok) {
        SLOGW("check mediaImage with no property");
    }
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetIconUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "iconUri", property);
    if (status == napi_ok) {
        SLOGD("Get icon uri succeed");
        out.SetIconUri(property);
    } else {
        out.SetIconUri("");
        SLOGW("GetIconUri failed, set icon uri to null");
    }
    return napi_ok;
}

napi_status NapiMediaDescription::SetIconUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetIconUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    if (in.GetIconUri().length() <= 0 || in.GetIcon() != nullptr) {
        status = napi_set_named_property(env, out, "iconUri", property);
    } else {
        status = napi_set_named_property(env, out, "iconUri", property);
        if (status != napi_ok) {
            SLOGW("check iconUri with no property");
        }
        status = napi_set_named_property(env, out, "mediaImage", property);
        if (status != napi_ok) {
            SLOGW("check mediaImage with no property");
        }
    }

    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetMediaImage(napi_env env, napi_value in, AVMediaDescription& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "mediaImage", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get mediaImage property failed", napi_ok);
    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, property, &type);
    CHECK_RETURN(status == napi_ok, "get napi_value type failed", status);
    if (type == napi_string) {
        std::string uri;
        status = NapiUtils::GetValue(env, property, uri);
        if (status != napi_ok) {
            SLOGW("GetMediaImage failed, set media image uri to null");
            out.SetIconUri("");
            return napi_ok;
        }
        SLOGD("Get media image, set icon uri");
        out.SetIconUri(uri);
    } else if (type == napi_object) {
        auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
        if (pixelMap == nullptr) {
            SLOGE("unwrap failed");
            return napi_invalid_arg;
        }
        out.SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
    } else {
        SLOGE("mediaImage property value type invalid");
        out.SetIconUri("");
    }

    return status;
}

napi_status NapiMediaDescription::GetExtras(napi_env env, napi_value in, AVMediaDescription& out)
{
    AAFwk::WantParams property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "extras", property);
    if (status != napi_ok) {
        SLOGD("extras is null");
        return napi_ok;
    }
    out.SetExtras(std::make_shared<AAFwk::WantParams>(property));
    return status;
}

napi_status NapiMediaDescription::SetExtras(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto extras = in.GetExtras();
    if (extras == nullptr) {
        SLOGD("extras is null");
        return napi_ok;
    }
    AAFwk::WantParams params = *extras;
    auto status = NapiUtils::SetValue(env, params, property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "extras", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetMediaType(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaType", property);
    CheckAndSetDefaultString(status, property);
    out.SetMediaType(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetMediaType(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaType(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaType", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetMediaSize(napi_env env, napi_value in, AVMediaDescription& out)
{
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaSize", property);
    CheckAndSetDefaultInt(status, property);
    out.SetMediaSize(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetMediaSize(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaSize(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaSize", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetAlbumTitle(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "albumTitle", property);
    CheckAndSetDefaultString(status, property);
    out.SetAlbumTitle(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetAlbumTitle(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAlbumTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "albumTitle", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetAlbumCoverUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "albumCoverUri", property);
    CheckAndSetDefaultString(status, property);
    out.SetAlbumCoverUri(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetAlbumCoverUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAlbumCoverUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "albumCoverUri", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetLyricContent(napi_env env, napi_value in, AVMediaDescription& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "lyricContent", property);
    CheckAndSetDefaultString(status, property);
    out.SetLyricContent(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetLyricContent(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetLyricContent(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "lyricContent", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetLyricUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get LyricUri from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "lyricUri", property);
    CheckAndSetDefaultString(status, property);
    out.SetLyricUri(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetLyricUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set LyricUri from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetLyricUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "lyricUri", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetArtist(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get Artist from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "artist", property);
    CheckAndSetDefaultString(status, property);
    out.SetArtist(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetArtist(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set Artist from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetArtist(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "artist", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetMediaUri(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get MediaUri from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaUri", property);
    CheckAndSetDefaultString(status, property);
    out.SetMediaUri(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetMediaUri(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set MediaUri from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetMediaUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaUri", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetFdSrc(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get FdSrc from napi_value");
    AVFileDescriptor property;
    auto status = NapiUtils::GetNamedProperty(env, in, "fdSrc", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetFdSrc(property);
    return status;
}

napi_status NapiMediaDescription::SetFdSrc(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set FdSrc from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetFdSrc(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "fdSrc", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetDuration(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get Duration from napi_value");
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "duration", property);
    CheckAndSetDefaultInt(status, property);
    out.SetDuration(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetDuration(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set Duration from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDuration(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "duration", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetStartPosition(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get StartPosition from napi_value");
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "startPosition", property);
    CheckAndSetDefaultInt(status, property);
    out.SetStartPosition(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetStartPosition(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set StartPosition from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetStartPosition(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "startPosition", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetCreditsPosition(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get CreditsPosition from napi_value");
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "creditsPosition", property);
    CheckAndSetDefaultInt(status, property);
    out.SetCreditsPosition(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetCreditsPosition(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set CreditsPosition from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetCreditsPosition(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "creditsPosition", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetAppName(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get app name from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "appName", property);
    CheckAndSetDefaultString(status, property);
    out.SetAppName(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetAppName(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set app name from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAppName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "appName", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetLaunchClientData(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start get launchClientData from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "launchClientData", property);
    CheckAndSetDefaultString(status, property);
    out.SetLaunchClientData(property);
    return status;
}

napi_status NapiMediaDescription::SetLaunchClientData(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set launchClientData from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetLaunchClientData(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "launchClientData", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);

    return status;
}

napi_status NapiMediaDescription::GetDrmScheme(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get drm type from napi_value");
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "drmScheme", property);
    CheckAndSetDefaultString(status, property);
    out.SetDrmScheme(property);
    return napi_ok;
}

napi_status NapiMediaDescription::SetDrmScheme(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set drm type from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDrmScheme(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "drmScheme", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetDataSrc(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get data src from napi_value");
    AVDataSrcDescriptor property;
    auto status = NapiUtils::GetNamedProperty(env, in, "dataSrc", property);
    if (status == napi_ok) {
        out.SetDataSrc(property);
    } else {
        SLOGI("GetDataSrc no datasrc");
    }

    return napi_ok;
}

napi_status NapiMediaDescription::SetDataSrc(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set data src from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDataSrc(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "dataSrc", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMediaDescription::GetPcmSrc(napi_env env, napi_value in, AVMediaDescription& out)
{
    SLOGD("Start get pcm src from napi_value");
    bool property;
    auto status = NapiUtils::GetNamedProperty(env, in, "pcmSrc", property);
    if (status == napi_ok) {
        out.SetPcmSrc(property);
    }
    return napi_ok;
}

napi_status NapiMediaDescription::SetPcmSrc(napi_env env, const AVMediaDescription& in, napi_value& out)
{
    SLOGD("Start set pcm src from napi_value");
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetPcmSrc(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "pcmSrc", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}