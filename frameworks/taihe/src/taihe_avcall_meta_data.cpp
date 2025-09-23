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
#define LOG_TAG "TaiheAVCallMetaData"
#endif

#include "taihe_avcall_meta_data.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaiheAVCallMetaData::GetterType> TaiheAVCallMetaData::getterMap_ = {
    {"name", GetName},
    {"phoneNumber", GetPhoneNumber},
    {"avatar", GetMediaImage},
};

std::map<int32_t, TaiheAVCallMetaData::SetterType> TaiheAVCallMetaData::setterMap_ = {
    {OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_NAME, SetName},
    {OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_PHONE_NUMBER, SetPhoneNumber},
    {OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE, SetMediaImage},
};

std::pair<std::string, int32_t> TaiheAVCallMetaData::filterMap_[] = {
    {"name", OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_NAME},
    {"phoneNumber", OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_PHONE_NUMBER},
    {"avatar", OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_MEDIA_IMAGE},
};

int32_t TaiheAVCallMetaData::ConvertFilter(
    string_view filter, OHOS::AVSession::AVCallMetaData::AVCallMetaMaskType &mask)
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

int32_t TaiheAVCallMetaData::ConvertFilter(
    array<string> filter, OHOS::AVSession::AVCallMetaData::AVCallMetaMaskType &mask)
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

int32_t TaiheAVCallMetaData::GetCallMetadata(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVCallMetaData get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVCallMetaData get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::SetCallMetadata(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out)
{
    auto mask = in.GetAVCallMetaMask();
    if (mask.none()) {
        SLOGI("SetAVCallMetaData undefined meta");
        out = CreateUndefinedCallMetadata();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    for (int32_t i = 0; i < OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVCallMetaData set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

CallMetadata TaiheAVCallMetaData::CreateUndefinedCallMetadata()
{
    CallMetadata callMeta {
        .name = optional<string>(std::nullopt),
        .phoneNumber = optional<string>(std::nullopt),
        .avatar = optional<uintptr_t>(std::nullopt),
    };
    return callMeta;
}

int32_t TaiheAVCallMetaData::GetName(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.name, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get name failed", status);
    out.SetName(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::SetName(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out)
{
    out.name = optional<string>(std::in_place_t {}, string(in.GetName()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::GetPhoneNumber(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out)
{
    std::string property;
    int32_t status = TaiheUtils::GetOptionalString(in.phoneNumber, property);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "get phoneNumber failed", status);
    out.SetPhoneNumber(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::SetPhoneNumber(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out)
{
    out.phoneNumber = optional<string>(std::in_place_t {}, string(in.GetPhoneNumber()));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::GetMediaImage(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out)
{
    if (in.avatar.has_value()) {
        auto pixelMap = TaiheUtils::GetImagePixelMap(in.avatar.value());
        CHECK_RETURN(pixelMap != nullptr, "Unwrap avatar pixelMap failed", OHOS::AVSession::ERR_INVALID_PARAM);
        out.SetMediaImage(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallMetaData::SetMediaImage(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out)
{
    auto avPixelMap = in.GetMediaImage();
    if (avPixelMap == nullptr) {
        SLOGI("media image is none");
        out.avatar = optional<uintptr_t>(std::nullopt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    auto pixelMap = OHOS::AVSession::AVSessionPixelMapAdapter::ConvertFromInner(avPixelMap);
    auto aniPixelMap = TaiheUtils::ToAniImagePixelMap(pixelMap);
    out.avatar = (aniPixelMap == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(aniPixelMap));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession