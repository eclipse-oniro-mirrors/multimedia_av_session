/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef LOG_TAG
#define LOG_TAG "TaiheMetaData"
#endif

#include "taihe_meta_data.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaiheMetaData::GetterType> TaiheMetaData::getterMap_ = {
    {"assetId", GetAssetId},
    {"title", GetTitle},
    {"artist", GetArtist},
    {"author", GetAuthor},
    {"avQueueName", GetAVQueueName},
    {"avQueueId", GetAVQueueId},
    {"avQueueImage", GetAVQueueImage},
    {"bundleIcon", GetBundleIcon},
    {"album", GetAlbum},
    {"writer", GetWriter},
    {"composer", GetComposer},
    {"duration", GetDuration},
    {"mediaImage", GetMediaImage},
    {"publishDate", GetPublishDate},
    {"subtitle", GetSubtitle},
    {"description", GetDescription},
    {"lyric", GetLyric},
    {"previousAssetId", GetPreviousAssetId},
    {"nextAssetId", GetNextAssetId},
    {"skipIntervals", GetSkipIntervals},
    {"filter", GetFilter},
    {"displayTags", GetDisplayTags},
    {"drmSchemes", GetDrmSchemes},
    {"singleLyricText", GetSingleLyricText}
};

std::map<int32_t, TaiheMetaData::SetterType> TaiheMetaData::setterMap_ = {
    {OHOS::AVSession::AVMetaData::META_KEY_ASSET_ID, SetAssetId},
    {OHOS::AVSession::AVMetaData::META_KEY_TITLE, SetTitle},
    {OHOS::AVSession::AVMetaData::META_KEY_ARTIST, SetArtist},
    {OHOS::AVSession::AVMetaData::META_KEY_AUTHOR, SetAuthor},
    {OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_NAME, SetAVQueueName},
    {OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_ID, SetAVQueueId},
    {OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_IMAGE, SetAVQueueImage},
    {OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_IMAGE_URI, SetAVQueueImageUri},
    {OHOS::AVSession::AVMetaData::META_KEY_ALBUM, SetAlbum},
    {OHOS::AVSession::AVMetaData::META_KEY_WRITER, SetWriter},
    {OHOS::AVSession::AVMetaData::META_KEY_COMPOSER, SetComposer},
    {OHOS::AVSession::AVMetaData::META_KEY_DURATION, SetDuration},
    {OHOS::AVSession::AVMetaData::META_KEY_MEDIA_IMAGE, SetMediaImage},
    {OHOS::AVSession::AVMetaData::META_KEY_MEDIA_IMAGE_URI, SetMediaImageUri},
    {OHOS::AVSession::AVMetaData::META_KEY_PUBLISH_DATE, SetPublishDate},
    {OHOS::AVSession::AVMetaData::META_KEY_SUBTITLE, SetSubtitle},
    {OHOS::AVSession::AVMetaData::META_KEY_DESCRIPTION, SetDescription},
    {OHOS::AVSession::AVMetaData::META_KEY_LYRIC, SetLyric},
    {OHOS::AVSession::AVMetaData::META_KEY_PREVIOUS_ASSET_ID, SetPreviousAssetId},
    {OHOS::AVSession::AVMetaData::META_KEY_NEXT_ASSET_ID, SetNextAssetId},
    {OHOS::AVSession::AVMetaData::META_KEY_SKIP_INTERVALS, SetSkipIntervals},
    {OHOS::AVSession::AVMetaData::META_KEY_FILTER, SetFilter},
    {OHOS::AVSession::AVMetaData::META_KEY_DISPLAY_TAGS, SetDisplayTags},
    {OHOS::AVSession::AVMetaData::META_KEY_DRM_SCHEMES, SetDrmSchemes},
    {OHOS::AVSession::AVMetaData::META_KEY_BUNDLE_ICON, SetBundleIcon},
    {OHOS::AVSession::AVMetaData::META_KEY_SINGLE_LYRIC_TEXT, SetSingleLyricText}
};

std::pair<std::string, int32_t> TaiheMetaData::filterMap_[] = {
    {"assetId", OHOS::AVSession::AVMetaData::META_KEY_ASSET_ID},
    {"title", OHOS::AVSession::AVMetaData::META_KEY_TITLE},
    {"artist", OHOS::AVSession::AVMetaData::META_KEY_ARTIST},
    {"author", OHOS::AVSession::AVMetaData::META_KEY_AUTHOR},
    {"avQueueName", OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_NAME},
    {"avQueueId", OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_ID},
    {"avQueueImage", OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_IMAGE},
    {"avQueueImage", OHOS::AVSession::AVMetaData::META_KEY_AVQUEUE_IMAGE_URI},
    {"album", OHOS::AVSession::AVMetaData::META_KEY_ALBUM},
    {"writer", OHOS::AVSession::AVMetaData::META_KEY_WRITER},
    {"composer", OHOS::AVSession::AVMetaData::META_KEY_COMPOSER},
    {"duration", OHOS::AVSession::AVMetaData::META_KEY_DURATION},
    {"mediaImage", OHOS::AVSession::AVMetaData::META_KEY_MEDIA_IMAGE},
    {"mediaImage", OHOS::AVSession::AVMetaData::META_KEY_MEDIA_IMAGE_URI},
    {"publishDate", OHOS::AVSession::AVMetaData::META_KEY_PUBLISH_DATE},
    {"subtitle", OHOS::AVSession::AVMetaData::META_KEY_SUBTITLE},
    {"description", OHOS::AVSession::AVMetaData::META_KEY_DESCRIPTION},
    {"lyric", OHOS::AVSession::AVMetaData::META_KEY_LYRIC},
    {"previousAssetId", OHOS::AVSession::AVMetaData::META_KEY_PREVIOUS_ASSET_ID},
    {"nextAssetId", OHOS::AVSession::AVMetaData::META_KEY_NEXT_ASSET_ID},
    {"skipIntervals", OHOS::AVSession::AVMetaData::META_KEY_SKIP_INTERVALS},
    {"filter", OHOS::AVSession::AVMetaData::META_KEY_FILTER},
    {"displayTags", OHOS::AVSession::AVMetaData::META_KEY_DISPLAY_TAGS},
    {"drmSchemes", OHOS::AVSession::AVMetaData::META_KEY_DRM_SCHEMES},
    {"bundleIcon", OHOS::AVSession::AVMetaData::META_KEY_BUNDLE_ICON},
    {"singleLyricText", OHOS::AVSession::AVMetaData::META_KEY_SINGLE_LYRIC_TEXT}
};

int32_t TaiheMetaData::ConvertFilter(string_view filter, OHOS::AVSession::AVMetaData::MetaMaskType &mask)
{
    std::string stringFilter;
    int32_t status = TaiheUtils::GetString(filter, stringFilter);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get string filter failed", status);
    if (stringFilter != "all") {
        SLOGE("string filter only support all") ;
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    mask.set();
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::ConvertFilter(array<string> filter, OHOS::AVSession::AVMetaData::MetaMaskType &mask)
{
    for (const auto &item : filter) {
        std::string metaKey;
        int32_t status = TaiheUtils::GetString(item, metaKey);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get string value failed", status);
        for (const auto &pair : filterMap_) {
            if (pair.first == metaKey) {
                mask.set(pair.second);
            }
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAVMetaData(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVMetaData get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVMetaData get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAVMetaData(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    auto mask = in.GetMetaMask();
    if (mask.none()) {
        SLOGI("SetAVMetaData undefined meta");
        out = CreateUndefinedAVMetaData();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    for (int32_t i = 0; i < OHOS::AVSession::AVMetaData::META_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVMetaData set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVMetadata TaiheMetaData::CreateUndefinedAVMetaData()
{
    AVMetadata meta {
        .assetId = string(""),
        .title = optional<string>(std::nullopt),
        .artist = optional<string>(std::nullopt),
        .author = optional<string>(std::nullopt),
        .avQueueName = optional<string>(std::nullopt),
        .avQueueId = optional<string>(std::nullopt),
        .avQueueImage = optional<AVImageType>(std::nullopt),
        .album = optional<string>(std::nullopt),
        .writer = optional<string>(std::nullopt),
        .composer = optional<string>(std::nullopt),
        .duration = optional<int64_t>(std::nullopt),
        .mediaImage = optional<AVImageType>(std::nullopt),
        .bundleIcon = optional<uintptr_t>(std::nullopt),
        .publishDate = optional<uintptr_t>(std::nullopt),
        .subtitle = optional<string>(std::nullopt),
        .description = optional<string>(std::nullopt),
        .lyric = optional<string>(std::nullopt),
        .singleLyricText = optional<string>(std::nullopt),
        .previousAssetId = optional<string>(std::nullopt),
        .nextAssetId = optional<string>(std::nullopt),
        .filter = optional<int32_t>(std::nullopt),
        .drmSchemes = optional<array<string>>(std::nullopt),
        .skipIntervals = optional<SkipIntervals>(std::nullopt),
        .displayTags = optional<int32_t>(std::nullopt),
    };
    return meta;
}

int32_t TaiheMetaData::GetAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetString(in.assetId, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get assetId failed", status);
    out.SetAssetId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.assetId = string(in.GetAssetId());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetTitle(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.title, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get title failed", status);
    out.SetTitle(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetTitle(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.title = optional<string>(std::in_place_t {}, string(in.GetTitle()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetArtist(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.artist, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get artist failed", status);
    out.SetArtist(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetArtist(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.artist = optional<string>(std::in_place_t {}, string(in.GetArtist()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAuthor(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.author, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get author failed", status);
    out.SetAuthor(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAuthor(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.author = optional<string>(std::in_place_t {}, string(in.GetAuthor()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAVQueueName(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.avQueueName, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get avQueueName failed", status);
    out.SetAVQueueName(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAVQueueName(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.avQueueName = optional<string>(std::in_place_t {}, string(in.GetAVQueueName()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAVQueueId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.avQueueId, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get avQueueId failed", status);
    out.SetAVQueueId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAVQueueId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.avQueueId = optional<string>(std::in_place_t {}, string(in.GetAVQueueId()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAVQueueImage(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    if (in.avQueueImage.has_value()) {
        if (in.avQueueImage.value().get_tag() == AVImageType::tag_t::typeString) {
            std::string uri;
            int32_t status = TaiheUtils::GetString(in.avQueueImage.value().get_typeString_ref(), uri);
            CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get avQueueImage uri failed", status);
            out.SetAVQueueImageUri(uri);
        } else if (in.avQueueImage.value().get_tag() == AVImageType::tag_t::typePixelMap) {
            auto pixelMap = TaiheUtils::GetImagePixelMap(in.avQueueImage.value().get_typePixelMap_ref());
            CHECK_RETURN(pixelMap != nullptr, "Unwrap av queue pixelMap failed", OHOS::AVSession::ERR_INVALID_PARAM);
            out.SetAVQueueImage(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        } else {
            SLOGE("Invalid avQueueImage property type");
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAVQueueImage(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    auto pixelMap = in.GetAVQueueImage();
    if (pixelMap == nullptr) {
        SLOGI("av queue image is none");
        out.avQueueImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType avQueueImage = TaiheUtils::ToTaiheAVImageType(pixelMap, "");
    out.avQueueImage = optional<AVImageType>(std::in_place_t {}, avQueueImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAVQueueImageUri(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    std::string uri = in.GetAVQueueImageUri();
    if (uri.empty()) {
        SLOGI("av queue image uri empty");
        out.avQueueImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType avQueueImage = TaiheUtils::ToTaiheAVImageType(nullptr, uri);
    out.avQueueImage = optional<AVImageType>(std::in_place_t {}, avQueueImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetBundleIcon(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    SLOGE("bundle icon readonly, can't be set");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetBundleIcon(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    auto avPixelMap = in.GetBundleIcon();
    if (avPixelMap == nullptr) {
        SLOGI("bundle icon is none");
        out.bundleIcon = optional<uintptr_t>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    auto pixelMap = OHOS::AVSession::AVSessionPixelMapAdapter::ConvertFromInner(avPixelMap);
    auto aniPixelMap = TaiheUtils::ToAniImagePixelMap(pixelMap);
    out.bundleIcon = (aniPixelMap == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(aniPixelMap));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetAlbum(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.album, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get album failed", status);
    out.SetAlbum(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetAlbum(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.album = optional<string>(std::in_place_t {}, string(in.GetAlbum()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetWriter(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.writer, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get writer failed", status);
    out.SetWriter(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetWriter(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.writer = optional<string>(std::in_place_t {}, string(in.GetWriter()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetComposer(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.composer, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get composer failed", status);
    out.SetComposer(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetComposer(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.composer = optional<string>(std::in_place_t {}, string(in.GetComposer()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetDuration(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    int64_t property = in.duration.has_value() ? in.duration.value() : 0;
    out.SetDuration(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetDuration(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.duration = optional<int64_t>(std::in_place_t {}, in.GetDuration());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetMediaImage(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    if (in.mediaImage.has_value()) {
        if (in.mediaImage.value().get_tag() == AVImageType::tag_t::typeString) {
            std::string uri;
            int32_t status = TaiheUtils::GetString(in.mediaImage.value().get_typeString_ref(), uri);
            CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get mediaImage uri failed", status);
            out.SetMediaImageUri(uri);
        } else if (in.mediaImage.value().get_tag() == AVImageType::tag_t::typePixelMap) {
            auto pixelMap = TaiheUtils::GetImagePixelMap(in.mediaImage.value().get_typePixelMap_ref());
            CHECK_RETURN(pixelMap != nullptr, "Unwrap media pixelMap failed", OHOS::AVSession::ERR_INVALID_PARAM);
            out.SetMediaImage(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        } else {
            SLOGE("Invalid mediaImage property type");
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetMediaImage(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    auto pixelMap = in.GetMediaImage();
    if (pixelMap == nullptr) {
        SLOGI("media image is none");
        out.mediaImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType mediaImage = TaiheUtils::ToTaiheAVImageType(pixelMap, "");
    out.mediaImage = optional<AVImageType>(std::in_place_t {}, mediaImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetMediaImageUri(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    std::string uri = in.GetMediaImageUri();
    if (uri.empty()) {
        SLOGI("media image uri empty");
        out.mediaImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType mediaImage = TaiheUtils::ToTaiheAVImageType(nullptr, uri);
    out.mediaImage = optional<AVImageType>(std::in_place_t {}, mediaImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetPublishDate(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    if (in.publishDate.has_value()) {
        ani_env *env = taihe::get_env();
        CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::AVSESSION_ERROR);

        ani_class cls {};
        CHECK_RETURN(env->FindClass("std.core.Date", &cls) == ANI_OK,
            "FindClass std.core.Date failed", OHOS::AVSession::AVSESSION_ERROR);
        ani_method method {};
        CHECK_RETURN(env->Class_FindMethod(cls, "valueOf", nullptr, &method) == ANI_OK,
            "Class_FindMethod Date valueOf failed", OHOS::AVSession::AVSESSION_ERROR);

        ani_object aniDate = reinterpret_cast<ani_object>(in.publishDate.value());
        CHECK_RETURN(aniDate != nullptr, "aniDate is nullptr", OHOS::AVSession::AVSESSION_ERROR);
        ani_double aniDouble = 0;
        CHECK_RETURN(env->Object_CallMethod_Double(aniDate, method, &aniDouble) == ANI_OK,
            "Object_CallMethod_Double Date valueOf failed", OHOS::AVSession::AVSESSION_ERROR);

        out.SetPublishDate(static_cast<double>(aniDouble));
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetPublishDate(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        SLOGW("env is nullptr, set publishDate undefined");
        out.publishDate = optional<uintptr_t>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    ani_class cls {};
    CHECK_RETURN(env->FindClass("std.core.Date", &cls) == ANI_OK,
        "FindClass std.core.Date failed", OHOS::AVSession::AVSESSION_ERROR);
    ani_method ctorMethod {};
    CHECK_RETURN(env->Class_FindMethod(cls, "<ctor>", "X{C{std.core.Double}C{std.core.String}C{std.core.Date}}",
        &ctorMethod) == ANI_OK, "Class_FindMethod std.core.Date <ctor> failed", OHOS::AVSession::AVSESSION_ERROR);
    ani_object aniDoubleObject {};
    int32_t ret = TaiheUtils::ToAniDoubleObject(env, in.GetPublishDate(), aniDoubleObject);
    CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "ToAniDoubleObject failed", ret);

    ani_object aniDate {};
    CHECK_RETURN(env->Object_New(cls, ctorMethod, &aniDate, aniDoubleObject) == ANI_OK,
        "Object_New std.core.Date failed", OHOS::AVSession::AVSESSION_ERROR);

    out.publishDate = optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(aniDate));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetSubtitle(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.subtitle, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get subtitle failed", status);
    out.SetSubTitle(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetSubtitle(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.subtitle = optional<string>(std::in_place_t {}, string(in.GetSubTitle()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetDescription(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.description, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get description failed", status);
    out.SetDescription(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetDescription(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.description = optional<string>(std::in_place_t {}, string(in.GetDescription()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetLyric(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.lyric, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get lyric failed", status);
    out.SetLyric(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetLyric(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.lyric = optional<string>(std::in_place_t {}, string(in.GetLyric()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetSingleLyricText(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.singleLyricText, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get singleLyricText failed", status);
    out.SetSingleLyricText(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetSingleLyricText(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.singleLyricText = optional<string>(std::in_place_t {}, string(in.GetSingleLyricText()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetPreviousAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.previousAssetId, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get previousAssetId failed", status);
    out.SetPreviousAssetId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetPreviousAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.previousAssetId = optional<string>(std::in_place_t {}, string(in.GetPreviousAssetId()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetNextAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.nextAssetId, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get nextAssetId failed", status);
    out.SetNextAssetId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetNextAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    out.nextAssetId = optional<string>(std::in_place_t {}, string(in.GetNextAssetId()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetSkipIntervals(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    int32_t property = in.skipIntervals.has_value() ? in.skipIntervals.value().get_value() : 0;
    SLOGD("GetSkipIntervals %{public}d", property);
    out.SetSkipIntervals(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetSkipIntervals(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    SLOGD("SetSkipIntervals %{public}d", in.GetSkipIntervals());
    SkipIntervals intervals = SkipIntervals::from_value(in.GetSkipIntervals());
    out.skipIntervals = optional<SkipIntervals>(std::in_place_t {}, intervals);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetFilter(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    int32_t property = in.filter.has_value() ? in.filter.value() : 0;
    SLOGD("GetFilter %{public}d", property);
    out.SetFilter(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetFilter(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    SLOGD("SetFilter %{public}d", in.GetFilter());
    out.filter = optional<int32_t>(std::in_place_t {}, in.GetFilter());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetDisplayTags(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    int32_t property = in.displayTags.has_value() ? in.displayTags.value() : 0;
    SLOGD("GetDisplayTags %{public}d", property);
    out.SetDisplayTags(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetDisplayTags(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    SLOGD("SetDisplayTags %{public}d", in.GetDisplayTags());
    out.displayTags = optional<int32_t>(std::in_place_t {}, in.GetDisplayTags());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::GetDrmSchemes(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)
{
    std::vector<std::string> property;
    if (in.drmSchemes.has_value()) {
        int32_t status = TaiheUtils::GetStringArray(in.drmSchemes.value(), property);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get drmSchemes failed", status);
    }
    out.SetDrmSchemes(property);
    SLOGI("property %{public}zu", property.size());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMetaData::SetDrmSchemes(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)
{
    SLOGD("SetDrmSchemes in, drmSchemes len: %{public}zu", in.GetDrmSchemes().size());
    std::vector<taihe::string> property;
    for (const auto &item : in.GetDrmSchemes()) {
        property.emplace_back(taihe::string(item));
    }
    out.drmSchemes = optional<array<string>>(std::in_place_t {}, array<string>(property));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession
