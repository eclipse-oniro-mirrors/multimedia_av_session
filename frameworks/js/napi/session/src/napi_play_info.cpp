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

#include "napi_play_info.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiPlayInfo::GetterType> NapiPlayInfo::getterMap_ = {
    { "mediaId", GetMediaId },
    { "mediaName", GetMediaName },
    { "mediaUrl", GetMediaUrl },
    { "mediaType", GetMediaType },
    { "startPosition",  GetStartPosition },
    { "duration", GetDuration },
    { "albumCoverUrl", GetAlbumCoverUrl },
    { "albumTitle", GetAlbumTitle },
    { "artist", GetArtist },
    { "lyricUrl", GetLyricUrl },
    { "lyricContent", GetLyricContent },
    { "icon", GetIcon },
    { "iconImage", GetIconImage },
    { "iconUrl", GetIconUri },
    { "appName", GetAppName },
};

std::map<int32_t, NapiPlayInfo::SetterType> NapiPlayInfo::setterMap_ = {
    { PlayInfo::PLAY_INFO_KEY_MEDIA_ID, SetMediaId },
    { PlayInfo::PLAY_INFO_KEY_MEDIA_NAME, SetMediaName },
    { PlayInfo::PLAY_INFO_KEY_MEDIA_URL, SetMediaUrl },
    { PlayInfo::PLAY_INFO_KEY_MEDIA_TYPE, SetMediaType },
    { PlayInfo::PLAY_INFO_KEY_START_POSITION, SetStartPosition },
    { PlayInfo::PLAY_INFO_KEY_DURATION, SetDuration },
    { PlayInfo::PLAY_INFO_KEY_ALBUM_COVER_URL, SetAlbumCoverUrl },
    { PlayInfo::PLAY_INFO_KEY_ALBUM_TITLE, SetAlbumTitle },
    { PlayInfo::PLAY_INFO_KEY_ARTIST, SetArtist },
    { PlayInfo::PLAY_INFO_KEY_LYRIC_URL, SetLyricUrl },
    { PlayInfo::PLAY_INFO_KEY_LYRIC_CONTENT, SetLyricContent },
    { PlayInfo::PLAY_INFO_KEY_ICON, SetIcon },
    { PlayInfo::PLAY_INFO_KEY_ICON_IMAGE, SetIconImage },
    { PlayInfo::PLAY_INFO_KEY_ICON_URL, SetIconUri },
    { PlayInfo::PLAY_INFO_KEY_APP_NAME, SetAppName },
};

napi_status NapiPlayInfo::GetValue(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of mediadescription", name.c_str());
            return napi_invalid_arg;
        }
        auto getter = it->second;
        if (getter(env, in, out) != napi_ok) {
            SLOGE("get property %{public}s failed", name.c_str());
            return napi_generic_failure;
        }
    }

    return napi_ok;
}

napi_status NapiPlayInfo::SetValue(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < PlayInfo::PLAY_INFO_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiPlayInfo::GetMediaId(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetMediaId(property);
    return status;
}

napi_status NapiPlayInfo::SetMediaId(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetMediaId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetMediaName(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaName", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetMediaName(property);
    return status;
}

napi_status NapiPlayInfo::SetMediaName(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetMediaName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaName", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetMediaUrl(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaUrl", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetMediaUrl(property);
    return status;
}

napi_status NapiPlayInfo::SetMediaUrl(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetMediaUrl(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaUrl", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetMediaType(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "mediaType", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetMediaType(property);
    return status;
}
napi_status NapiPlayInfo::SetMediaType(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetMediaType(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "mediaType", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetStartPosition(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "startPosition", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetStartPosition(property);
    return status;
}
napi_status NapiPlayInfo::SetStartPosition(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetStartPosition(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "startPosition", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetDuration(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "duration", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetDuration(property);
    return status;
}
napi_status NapiPlayInfo::SetDuration(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetDuration(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "duration", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetAlbumCoverUrl(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "albumCoverUrl", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetAlbumCoverUrl(property);
    return status;
}
napi_status NapiPlayInfo::SetAlbumCoverUrl(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetAlbumCoverUrl(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "albumCoverUrl", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetAlbumTitle(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "albumTitle", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetAlbumTitle(property);
    return status;
}
napi_status NapiPlayInfo::SetAlbumTitle(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetAlbumTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "albumTitle", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetArtist(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "artist", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetArtist(property);
    return status;
}
napi_status NapiPlayInfo::SetArtist(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetArtist(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "artist", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetLyricUrl(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "lyricUrl", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetLyricUrl(property);
    return status;
}
napi_status NapiPlayInfo::SetLyricUrl(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetLyricUrl(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "lyricUrl", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetLyricContent(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "lyricContent", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetLyricContent(property);
    return status;
}
napi_status NapiPlayInfo::SetLyricContent(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetLyricContent(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "lyricContent", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetIcon(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "icon", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetIcon(property);
    return status;
}
napi_status NapiPlayInfo::SetIcon(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetIcon(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "icon", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetIconImage(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "iconImage", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property failed", status);
    auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
    if (pixelMap == nullptr) {
        SLOGE("unwrap failed");
        return napi_invalid_arg;
    }
    out->SetIconImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    return status;
}

napi_status NapiPlayInfo::SetIconImage(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    auto pixelMap = in->GetIconImage();
    if (pixelMap == nullptr) {
        SLOGI("media image is null");
        return napi_ok;
    }
    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "iconImage", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetIconUri(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "iconUrl", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetIconUri(property);
    return status;
}
napi_status NapiPlayInfo::SetIconUri(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetIconUri(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "iconUrl", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiPlayInfo::GetAppName(napi_env env, napi_value in, std::shared_ptr<PlayInfo>& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "appName", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out->SetAppName(property);
    return status;
}
napi_status NapiPlayInfo::SetAppName(napi_env env, const std::shared_ptr<PlayInfo>& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in->GetAppName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "appName", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
