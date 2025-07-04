/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "napi_meta_data.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiMetaData::GetterType> NapiMetaData::getterMap_ = {
    { "assetId", GetAssetId },
    { "title", GetTitle },
    { "artist", GetArtist },
    { "author", GetAuthor },
    { "avQueueName",  GetAVQueueName },
    { "avQueueId",  GetAVQueueId },
    { "avQueueImage",  GetAVQueueImage },
    { "bundleIcon",  GetBundleIcon },
    { "album",  GetAlbum },
    { "writer", GetWriter },
    { "composer", GetComposer },
    { "duration", GetDuration },
    { "mediaImage", GetMediaImage },
    { "publishDate", GetPublishDate },
    { "subtitle", GetSubtitle },
    { "description", GetDescription },
    { "lyric", GetLyric },
    { "previousAssetId", GetPreviousAssetId },
    { "nextAssetId", GetNextAssetId },
    { "skipIntervals", GetSkipIntervals },
    { "filter", GetFilter },
    { "displayTags", GetDisplayTags },
    { "drmSchemes", GetDrmSchemes },
    { "singleLyricText", GetSingleLyricText }
};

std::map<int32_t, NapiMetaData::SetterType> NapiMetaData::setterMap_ = {
    { AVMetaData::META_KEY_ASSET_ID, SetAssetId },
    { AVMetaData::META_KEY_TITLE, SetTitle },
    { AVMetaData::META_KEY_ARTIST, SetArtist },
    { AVMetaData::META_KEY_AUTHOR, SetAuthor },
    { AVMetaData::META_KEY_AVQUEUE_NAME, SetAVQueueName },
    { AVMetaData::META_KEY_AVQUEUE_ID, SetAVQueueId },
    { AVMetaData::META_KEY_AVQUEUE_IMAGE, SetAVQueueImage },
    { AVMetaData::META_KEY_AVQUEUE_IMAGE_URI, SetAVQueueImageUri },
    { AVMetaData::META_KEY_ALBUM, SetAlbum },
    { AVMetaData::META_KEY_WRITER, SetWriter },
    { AVMetaData::META_KEY_COMPOSER, SetComposer },
    { AVMetaData::META_KEY_DURATION, SetDuration },
    { AVMetaData::META_KEY_MEDIA_IMAGE, SetMediaImage },
    { AVMetaData::META_KEY_MEDIA_IMAGE_URI, SetMediaImageUri },
    { AVMetaData::META_KEY_PUBLISH_DATE, SetPublishDate },
    { AVMetaData::META_KEY_SUBTITLE, SetSubtitle },
    { AVMetaData::META_KEY_DESCRIPTION, SetDescription },
    { AVMetaData::META_KEY_LYRIC, SetLyric },
    { AVMetaData::META_KEY_PREVIOUS_ASSET_ID, SetPreviousAssetId },
    { AVMetaData::META_KEY_NEXT_ASSET_ID, SetNextAssetId },
    { AVMetaData::META_KEY_SKIP_INTERVALS, SetSkipIntervals },
    { AVMetaData::META_KEY_FILTER, SetFilter },
    { AVMetaData::META_KEY_DISPLAY_TAGS, SetDisplayTags },
    { AVMetaData::META_KEY_DRM_SCHEMES, SetDrmSchemes },
    { AVMetaData::META_KEY_BUNDLE_ICON, SetBundleIcon },
    { AVMetaData::META_KEY_SINGLE_LYRIC_TEXT, SetSingleLyricText }
};

std::pair<std::string, int32_t> NapiMetaData::filterMap_[] = {
    { "assetId", AVMetaData::META_KEY_ASSET_ID },
    { "title", AVMetaData::META_KEY_TITLE },
    { "artist", AVMetaData::META_KEY_ARTIST },
    { "author", AVMetaData::META_KEY_AUTHOR },
    { "avQueueName", AVMetaData::META_KEY_AVQUEUE_NAME },
    { "avQueueId",  AVMetaData::META_KEY_AVQUEUE_ID },
    { "avQueueImage", AVMetaData::META_KEY_AVQUEUE_IMAGE },
    { "avQueueImage", AVMetaData::META_KEY_AVQUEUE_IMAGE_URI },
    { "album",  AVMetaData::META_KEY_ALBUM },
    { "writer", AVMetaData::META_KEY_WRITER },
    { "composer", AVMetaData::META_KEY_COMPOSER },
    { "duration", AVMetaData::META_KEY_DURATION },
    { "mediaImage", AVMetaData::META_KEY_MEDIA_IMAGE },
    { "mediaImage", AVMetaData::META_KEY_MEDIA_IMAGE_URI },
    { "publishDate", AVMetaData::META_KEY_PUBLISH_DATE },
    { "subtitle", AVMetaData::META_KEY_SUBTITLE },
    { "description", AVMetaData::META_KEY_DESCRIPTION },
    { "lyric", AVMetaData::META_KEY_LYRIC },
    { "previousAssetId", AVMetaData::META_KEY_PREVIOUS_ASSET_ID },
    { "nextAssetId", AVMetaData::META_KEY_NEXT_ASSET_ID },
    { "skipIntervals", AVMetaData::META_KEY_SKIP_INTERVALS },
    { "filter", AVMetaData::META_KEY_FILTER },
    { "displayTags", AVMetaData::META_KEY_DISPLAY_TAGS },
    { "drmSchemes", AVMetaData::META_KEY_DRM_SCHEMES },
    { "bundleIcon", AVMetaData::META_KEY_BUNDLE_ICON },
    { "singleLyricText", AVMetaData::META_KEY_SINGLE_LYRIC_TEXT }
};

napi_status NapiMetaData::ConvertFilter(napi_env env, napi_value filter, AVMetaData::MetaMaskType& mask)
{
    napi_valuetype type = napi_undefined;
    auto status = napi_typeof(env, filter, &type);
    CHECK_RETURN(status == napi_ok, "napi_typeof failed", status);

    if (type == napi_string) {
        std::string stringFilter;
        status = NapiUtils::GetValue(env, filter, stringFilter);
        CHECK_RETURN(status == napi_ok, "get string filter failed", status);
        if (stringFilter != "all") {
            SLOGE("string filter only support all") ;
            return napi_invalid_arg;
        }
        mask.set();
        return napi_ok;
    }

    uint32_t count = 0;
    status = napi_get_array_length(env, filter, &count);
    CHECK_RETURN(status == napi_ok, "get array length failed", status);
    for (uint32_t i = 0; i < count; i++) {
        napi_value value {};
        status = napi_get_element(env, filter, i, &value);
        CHECK_RETURN(status == napi_ok, "get element failed", status);
        std::string metaKey;
        status = NapiUtils::GetValue(env, value, metaKey);
        CHECK_RETURN(status == napi_ok, "get string value failed", status);
        for (const auto& pair : filterMap_) {
            if (pair.first == metaKey) {
                mask.set(pair.second);
            }
        }
    }

    return napi_ok;
}

napi_status NapiMetaData::GetValue(napi_env env, napi_value in, AVMetaData& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of metadata", name.c_str());
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

napi_status NapiMetaData::SetValue(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    auto mask = in.GetMetaMask();
    if (mask.none()) {
        SLOGI("undefined meta");
        return SetUndefinedMeta(env, out);
    }

    for (int i = 0; i < AVMetaData::META_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }

    return napi_ok;
}

napi_status NapiMetaData::SetUndefinedMeta(napi_env env, napi_value& meta)
{
    auto status = napi_set_named_property(env, meta, "assetId", NapiUtils::GetUndefinedValue(env));
    CHECK_RETURN(status == napi_ok, "set assetId to undefined failed", status);
    return napi_ok;
}

napi_status NapiMetaData::GetAssetId(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "assetId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAssetId(property);
    return status;
}

napi_status NapiMetaData::SetAssetId(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAssetId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "assetId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetTitle(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "title", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetTitle(property);
    return status;
}

napi_status NapiMetaData::SetTitle(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "title", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetArtist(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "artist", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetArtist(property);
    return status;
}

napi_status NapiMetaData::SetArtist(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetArtist(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "artist", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetAuthor(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "author", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAuthor(property);
    return status;
}

napi_status NapiMetaData::SetAuthor(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAuthor(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "author", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetAVQueueName(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "avQueueName", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAVQueueName(property);
    return status;
}

napi_status NapiMetaData::SetAVQueueName(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAVQueueName(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "avQueueName", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetAVQueueId(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "avQueueId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAVQueueId(property);
    return status;
}

napi_status NapiMetaData::SetAVQueueId(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAVQueueId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "avQueueId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetAVQueueImage(napi_env env, napi_value in, AVMetaData& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "avQueueImage", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property failed", status);
    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, property, &type);
    CHECK_RETURN(status == napi_ok, "get napi_value type failed", status);
    if (type == napi_string) {
        std::string uri;
        status = NapiUtils::GetValue(env, property, uri);
        CHECK_RETURN(status == napi_ok, "get property failed", status);
        out.SetAVQueueImageUri(uri);
    } else if (type == napi_object) {
        auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
        if (pixelMap == nullptr) {
            SLOGE("unwrap avqueue pixelMap failed");
            return napi_invalid_arg;
        }
        out.SetAVQueueImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        SLOGD(" napi get avqueueimage");
    } else {
        SLOGE("avqueueimage property value type invalid");
        return napi_invalid_arg;
    }

    return status;
}

napi_status NapiMetaData::SetAVQueueImage(napi_env env, const AVMetaData& in, napi_value& out)
{
    auto pixelMap = in.GetAVQueueImage();
    if (pixelMap == nullptr) {
        SLOGI("avqueue image is none");
        return napi_ok;
    }

    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "avQueueImage", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetBundleIcon(napi_env env, napi_value in, AVMetaData& out)
{
    SLOGE("bundle icon readonly, can't be set");
    return napi_ok;
}

napi_status NapiMetaData::SetBundleIcon(napi_env env, const AVMetaData& in, napi_value& out)
{
    auto pixelMap = in.GetBundleIcon();
    if (pixelMap == nullptr) {
        SLOGI("bundle icon is none");
        return napi_ok;
    }

    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "bundleIcon", property);
    CHECK_RETURN(status == napi_ok, "set bundleIcon property failed", status);
    return status;
}

napi_status NapiMetaData::SetAVQueueImageUri(napi_env env, const AVMetaData& in, napi_value& out)
{
    auto uri = in.GetAVQueueImageUri();
    if (uri.empty()) {
        SLOGI("avqueue image uri empty");
        return napi_ok;
    }

    napi_value property {};
    auto status = NapiUtils::SetValue(env, uri, property);
    CHECK_RETURN(status == napi_ok, "create property failed", status);
    status = napi_set_named_property(env, out, "avQueueImage", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetAlbum(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "album", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetAlbum(property);
    return status;
}

napi_status NapiMetaData::SetAlbum(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetAlbum(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "album", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetWriter(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "writer", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetWriter(property);
    return status;
}

napi_status NapiMetaData::SetWriter(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetWriter(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "writer", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetComposer(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "composer", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetComposer(property);
    return status;
}

napi_status NapiMetaData::SetComposer(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetComposer(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "composer", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetDuration(napi_env env, napi_value in, AVMetaData& out)
{
    int64_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "duration", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetDuration(property);
    return status;
}

napi_status NapiMetaData::SetDuration(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDuration(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "duration", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetMediaImage(napi_env env, napi_value in, AVMetaData& out)
{
    napi_value property {};
    auto status = napi_get_named_property(env, in, "mediaImage", &property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "get property failed", status);
    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, property, &type);
    CHECK_RETURN(status == napi_ok, "get napi_value type failed", status);
    if (type == napi_string) {
        std::string uri;
        status = NapiUtils::GetValue(env, property, uri);
        CHECK_RETURN(status == napi_ok, "get property failed", status);
        out.SetMediaImageUri(uri);
    } else if (type == napi_object) {
        auto pixelMap = Media::PixelMapNapi::GetPixelMap(env, property);
        if (pixelMap == nullptr) {
            SLOGE("unwrap failed");
            return napi_invalid_arg;
        }
        SLOGI("set mediaImage without small size");
        out.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    } else {
        SLOGE("mediaImage property value type invalid");
        return napi_invalid_arg;
    }

    return status;
}

napi_status NapiMetaData::SetMediaImage(napi_env env, const AVMetaData& in, napi_value& out)
{
    auto pixelMap = in.GetMediaImage();
    if (pixelMap == nullptr) {
        SLOGI("media image is none");
        return napi_ok;
    }

    napi_value property = Media::PixelMapNapi::CreatePixelMap(env,
        AVSessionPixelMapAdapter::ConvertFromInner(pixelMap));
    auto status = napi_set_named_property(env, out, "mediaImage", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::SetMediaImageUri(napi_env env, const AVMetaData& in, napi_value& out)
{
    auto uri = in.GetMediaImageUri();
    if (uri.empty()) {
        SLOGI("media image uri empty");
        return napi_ok;
    }

    napi_value property {};
    auto status = NapiUtils::SetValue(env, uri, property);
    CHECK_RETURN(status == napi_ok, "create property failed", status);
    status = napi_set_named_property(env, out, "mediaImage", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetPublishDate(napi_env env, napi_value in, AVMetaData& out)
{
    napi_value property;
    auto status = napi_get_named_property(env, in, "publishDate", &property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    double date {};
    status = NapiUtils::GetDateValue(env, property, date);
    CHECK_RETURN(status == napi_ok, "get date value failed", status);
    out.SetPublishDate(date);
    return status;
}

napi_status NapiMetaData::SetPublishDate(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetDateValue(env, in.GetPublishDate(), property);
    CHECK_RETURN(status == napi_ok, "create date object failed", status);
    status = napi_set_named_property(env, out, "publishDate", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetSubtitle(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "subtitle", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetSubTitle(property);
    return status;
}

napi_status NapiMetaData::SetSubtitle(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetSubTitle(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "subtitle", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetDescription(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "description", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetDescription(property);
    return status;
}

napi_status NapiMetaData::SetDescription(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetDescription(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "description", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetLyric(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "lyric", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetLyric(property);
    return status;
}

napi_status NapiMetaData::SetLyric(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetLyric(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "lyric", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetSingleLyricText(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "singleLyricText", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetSingleLyricText(property);
    return status;
}

napi_status NapiMetaData::SetSingleLyricText(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetSingleLyricText(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "singleLyricText", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetPreviousAssetId(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "previousAssetId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetPreviousAssetId(property);
    return status;
}

napi_status NapiMetaData::SetPreviousAssetId(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetPreviousAssetId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "previousAssetId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetNextAssetId(napi_env env, napi_value in, AVMetaData& out)
{
    std::string property;
    auto status = NapiUtils::GetNamedProperty(env, in, "nextAssetId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetNextAssetId(property);
    return status;
}

napi_status NapiMetaData::SetNextAssetId(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetNextAssetId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "nextAssetId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetSkipIntervals(napi_env env, napi_value in, AVMetaData& out)
{
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "skipIntervals", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    SLOGD("GetSkipIntervals %{public}d", static_cast<int32_t>(property));
    out.SetSkipIntervals(property);
    return status;
}

napi_status NapiMetaData::SetSkipIntervals(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    SLOGD("SetSkipIntervals %{public}d", static_cast<int32_t>(in.GetSkipIntervals()));
    auto status = NapiUtils::SetValue(env, in.GetSkipIntervals(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "skipIntervals", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetFilter(napi_env env, napi_value in, AVMetaData& out)
{
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "filter", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    SLOGD("GetFilter %{public}d", static_cast<int32_t>(property));
    out.SetFilter(property);
    return status;
}

napi_status NapiMetaData::SetFilter(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    SLOGD("SetFilter %{public}d", static_cast<int32_t>(in.GetFilter()));
    auto status = NapiUtils::SetValue(env, in.GetFilter(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "filter", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiMetaData::GetDisplayTags(napi_env env, napi_value in, AVMetaData& out)
{
    int32_t property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "displayTags", property);
    CHECK_RETURN(status == napi_ok, "get property displayTags failed", status);
    SLOGD("GetDisplayTags %{public}d", static_cast<int32_t>(property));
    out.SetDisplayTags(property);
    return status;
}

napi_status NapiMetaData::SetDisplayTags(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    SLOGD("SetDisplayTags %{public}d", static_cast<int32_t>(in.GetDisplayTags()));
    auto status = NapiUtils::SetValue(env, in.GetDisplayTags(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property displayTags failed", status);
    status = napi_set_named_property(env, out, "displayTags", property);
    CHECK_RETURN(status == napi_ok, "set property displayTags failed", status);
    return status;
}

napi_status NapiMetaData::GetDrmSchemes(napi_env env, napi_value in, AVMetaData& out)
{
    std::vector<std::string> property;
    auto status = NapiUtils::GetNamedProperty(env, in, "drmSchemes", property);
    CHECK_RETURN(status == napi_ok, "get property drmSchemes failed", status);
    out.SetDrmSchemes(property);
    SLOGI("property %{public}zu", property.size());
    return status;
}

napi_status NapiMetaData::SetDrmSchemes(napi_env env, const AVMetaData& in, napi_value& out)
{
    napi_value property {};
    SLOGD("SetDrmSchemes in, drmSchemes len: %{public}zu", in.GetDrmSchemes().size());
    auto status = NapiUtils::SetValue(env, in.GetDrmSchemes(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property drmSchemes failed", status);
    status = napi_set_named_property(env, out, "drmSchemes", property);
    CHECK_RETURN(status == napi_ok, "set property drmSchemes failed", status);
    return status;
}
}
