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
#define LOG_TAG "TaiheMediaDescription"
#endif

#include "taihe_media_description.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaiheMediaDescription::GetterType> TaiheMediaDescription::getterMap_ = {
    {"assetId", GetAssetId},
    {"title", GetTitle},
    {"subtitle", GetSubtitle},
    {"description", GetDescription},
    {"mediaImage", GetMediaImage},
    {"extras", GetExtras},
    {"mediaType", GetMediaType},
    {"mediaSize", GetMediaSize},
    {"albumTitle", GetAlbumTitle},
    {"albumCoverUri", GetAlbumCoverUri},
    {"lyricContent", GetLyricContent},
    {"lyricUri", GetLyricUri},
    {"artist", GetArtist},
    {"mediaUri", GetMediaUri},
    {"fdSrc", GetFdSrc},
    {"duration", GetDuration},
    {"startPosition", GetStartPosition},
    {"creditsPosition", GetCreditsPosition},
    {"appName", GetAppName},
    {"drmScheme", GetDrmScheme},
    {"dataSrc", GetDataSrc},
};

std::map<int32_t, TaiheMediaDescription::SetterType> TaiheMediaDescription::setterMap_ = {
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_ID, SetAssetId},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_TITLE, SetTitle},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_SUBTITLE, SetSubtitle},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_DESCRIPTION, SetDescription},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_ICON,  SetMediaImage},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_ICON_URI, SetMediaImageUri},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_EXTRAS, SetExtras},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_TYPE, SetMediaType},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_SIZE, SetMediaSize},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_ALBUM_TITLE, SetAlbumTitle},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_ALBUM_COVER_URI, SetAlbumCoverUri},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_LYRIC_CONTENT, SetLyricContent},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_LYRIC_URI, SetLyricUri},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_ARTIST, SetArtist},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_MEDIA_URI, SetMediaUri},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_FD_SRC, SetFdSrc},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_DURATION, SetDuration},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_START_POSITION, SetStartPosition},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_CREDITS_POSITION, SetCreditsPosition},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_APP_NAME, SetAppName},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_DRM_SCHEME, SetDrmScheme},
    {OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_DATA_SRC, SetDataSrc},
};

int32_t TaiheMediaDescription::GetAVMediaDescription(
    AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVMediaDescription get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVMediaDescription get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetAVMediaDescription(
    const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    for (int32_t i = 0; i < OHOS::AVSession::AVMediaDescription::MEDIA_DESCRIPTION_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVMediaDescription set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVMediaDescription TaiheMediaDescription::CreateUndefinedAVMediaDescription()
{
    AVMediaDescription description {
        .assetId = string(""),
        .title = optional<string>(std::nullopt),
        .subtitle = optional<string>(std::nullopt),
        .description = optional<string>(std::nullopt),
        .mediaImage = optional<AVImageType>(std::nullopt),
        .extras = optional<uintptr_t>(std::nullopt),
        .mediaType = optional<string>(std::nullopt),
        .mediaSize = optional<int32_t>(std::nullopt),
        .albumTitle = optional<string>(std::nullopt),
        .albumCoverUri = optional<string>(std::nullopt),
        .lyricContent = optional<string>(std::nullopt),
        .lyricUri = optional<string>(std::nullopt),
        .artist = optional<string>(std::nullopt),
        .mediaUri = optional<string>(std::nullopt),
        .fdSrc = optional<uintptr_t>(std::nullopt),
        .dataSrc = optional<uintptr_t>(std::nullopt),
        .drmScheme = optional<string>(std::nullopt),
        .duration = optional<int32_t>(std::nullopt),
        .startPosition = optional<int32_t>(std::nullopt),
        .creditsPosition = optional<int32_t>(std::nullopt),
        .appName = optional<string>(std::nullopt),
        .displayTags = optional<int32_t>(std::nullopt),
    };
    return description;
}

void TaiheMediaDescription::CheckAndSetDefaultString(int32_t status, std::string &defaultStr)
{
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGW("Get string from taihe failed, use default value");
        defaultStr = "";
    }
}

int32_t TaiheMediaDescription::GetAssetId(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetString(in.assetId, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get assetId failed", status);
    out.SetMediaId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetAssetId(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.assetId = string(in.GetMediaId());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetTitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.title, property);
    CheckAndSetDefaultString(status, property);
    out.SetTitle(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetTitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.title = optional<string>(std::in_place_t {}, string(in.GetTitle()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetSubtitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.subtitle, property);
    CheckAndSetDefaultString(status, property);
    out.SetSubtitle(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetSubtitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.subtitle = optional<string>(std::in_place_t {}, string(in.GetSubtitle()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetDescription(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.description, property);
    CheckAndSetDefaultString(status, property);
    out.SetDescription(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetDescription(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.description = optional<string>(std::in_place_t {}, string(in.GetDescription()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetMediaImage(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    if (in.mediaImage.has_value()) {
        if (in.mediaImage.value().get_tag() == AVImageType::tag_t::typeString) {
            std::string uri;
            int32_t status = TaiheUtils::GetString(in.mediaImage.value().get_typeString_ref(), uri);
            CheckAndSetDefaultString(status, uri);
            out.SetIconUri(uri);
        } else if (in.mediaImage.value().get_tag() == AVImageType::tag_t::typePixelMap) {
            auto pixelMap = TaiheUtils::GetImagePixelMap(in.mediaImage.value().get_typePixelMap_ref());
            CHECK_RETURN(pixelMap != nullptr, "Unwrap media pixelMap failed", OHOS::AVSession::ERR_INVALID_PARAM);
            out.SetIcon(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
        } else {
            SLOGE("Invalid mediaImage property type");
            out.SetIconUri("");
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetMediaImage(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    auto pixelMap = in.GetIcon();
    if (pixelMap == nullptr) {
        SLOGI("media image is null");
        out.mediaImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType mediaImage = TaiheUtils::ToTaiheAVImageType(pixelMap, "");
    out.mediaImage = optional<AVImageType>(std::in_place_t {}, mediaImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetMediaImageUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    std::string uri = in.GetIconUri();
    if (uri.empty()) {
        SLOGI("media image uri empty");
        out.mediaImage = optional<AVImageType>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    AVImageType mediaImage = TaiheUtils::ToTaiheAVImageType(nullptr, uri);
    out.mediaImage = optional<AVImageType>(std::in_place_t {}, mediaImage);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetExtras(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    if (in.extras.has_value()) {
        OHOS::AAFwk::WantParams property {};
        int32_t status = TaiheUtils::GetWantParams(in.extras.value(), property);
        if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGD("extras is null");
            return OHOS::AVSession::AVSESSION_SUCCESS;
        }
        out.SetExtras(std::make_shared<OHOS::AAFwk::WantParams>(property));
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetExtras(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    std::shared_ptr<OHOS::AAFwk::WantParams> extras = in.GetExtras();
    if (extras == nullptr) {
        SLOGE("extras is null");
        out.extras = optional<uintptr_t>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    auto property = TaiheUtils::ToAniWantParams(*extras);
    out.extras = (property == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(property));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetMediaType(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.mediaType, property);
    CheckAndSetDefaultString(status, property);
    out.SetMediaType(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetMediaType(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.mediaType = optional<string>(std::in_place_t {}, string(in.GetMediaType()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetMediaSize(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    int32_t property = in.mediaSize.has_value() ? in.mediaSize.value() : DEFAULT_INT32_VALUE;
    out.SetMediaSize(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetMediaSize(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.mediaSize = optional<int32_t>(std::in_place_t {}, in.GetMediaSize());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetAlbumTitle(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.albumTitle, property);
    CheckAndSetDefaultString(status, property);
    out.SetAlbumTitle(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetAlbumTitle(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.albumTitle = optional<string>(std::in_place_t {}, string(in.GetAlbumTitle()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetAlbumCoverUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.albumCoverUri, property);
    CheckAndSetDefaultString(status, property);
    out.SetAlbumCoverUri(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetAlbumCoverUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.albumCoverUri = optional<string>(std::in_place_t {}, string(in.GetAlbumCoverUri()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetLyricContent(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.lyricContent, property);
    CheckAndSetDefaultString(status, property);
    out.SetLyricContent(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetLyricContent(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.lyricContent = optional<string>(std::in_place_t {}, string(in.GetLyricContent()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetLyricUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.lyricUri, property);
    CheckAndSetDefaultString(status, property);
    out.SetLyricUri(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetLyricUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.lyricUri = optional<string>(std::in_place_t {}, string(in.GetLyricUri()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetArtist(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.artist, property);
    CheckAndSetDefaultString(status, property);
    out.SetArtist(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetArtist(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.artist = optional<string>(std::in_place_t {}, string(in.GetArtist()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetMediaUri(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.mediaUri, property);
    CheckAndSetDefaultString(status, property);
    out.SetMediaUri(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetMediaUri(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.mediaUri = optional<string>(std::in_place_t {}, string(in.GetMediaUri()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetFdSrc(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    if (in.fdSrc.has_value()) {
        OHOS::AVSession::AVFileDescriptor property;
        int32_t status = TaiheUtils::GetAVFileDescriptor(in.fdSrc.value(), property);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get fdSrc failed", status);
        out.SetFdSrc(property);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetFdSrc(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    auto property = TaiheUtils::ToAniAVFileDescriptor(in.GetFdSrc());
    out.fdSrc = (property == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(property));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetDataSrc(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    if (in.dataSrc.has_value()) {
        OHOS::AVSession::AVDataSrcDescriptor property;
        int32_t status = TaiheUtils::GetAVDataSrcDescriptor(in.dataSrc.value(), property);
        if (status == OHOS::AVSession::AVSESSION_SUCCESS) {
            out.SetDataSrc(property);
        } else {
            SLOGI("GetDataSrc no datasrc");
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetDataSrc(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    auto property = TaiheUtils::ToAniAVDataSrcDescriptor(in.GetDataSrc());
    out.dataSrc = (property == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(property));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetDrmScheme(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.drmScheme, property);
    CheckAndSetDefaultString(status, property);
    out.SetDrmScheme(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetDrmScheme(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.drmScheme = optional<string>(std::in_place_t {}, string(in.GetDrmScheme()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetDuration(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    int32_t property = in.duration.has_value() ? in.duration.value() : DEFAULT_INT32_VALUE;
    out.SetDuration(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetDuration(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.duration = optional<int32_t>(std::in_place_t {}, in.GetDuration());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetStartPosition(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    int32_t property = in.startPosition.has_value() ? in.startPosition.value() : DEFAULT_INT32_VALUE;
    out.SetStartPosition(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetStartPosition(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.startPosition = optional<int32_t>(std::in_place_t {}, in.GetStartPosition());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetCreditsPosition(
    AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    int32_t property = in.creditsPosition.has_value() ? in.creditsPosition.value() : DEFAULT_INT32_VALUE;
    out.SetCreditsPosition(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetCreditsPosition(
    const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.creditsPosition = optional<int32_t>(std::in_place_t {}, in.GetCreditsPosition());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::GetAppName(AVMediaDescription const &in, OHOS::AVSession::AVMediaDescription &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.appName, property);
    CheckAndSetDefaultString(status, property);
    out.SetAppName(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheMediaDescription::SetAppName(const OHOS::AVSession::AVMediaDescription &in, AVMediaDescription &out)
{
    out.appName = optional<string>(std::in_place_t {}, string(in.GetAppName()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession