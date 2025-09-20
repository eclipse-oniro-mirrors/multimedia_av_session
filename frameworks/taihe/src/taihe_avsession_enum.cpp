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
#ifndef LOG_TAG
#define LOG_TAG "TaiheAVSessionEnum"
#endif

#include "taihe_avsession_enum.h"

#include "avsession_log.h"

namespace ANI::AVSession {

static const std::map<OHOS::AVSession::HDRFormat, int32_t> ANI_HDR_FORMAT_INDEX_MAP = {
    {OHOS::AVSession::HDRFormat::NONE, 0},
    {OHOS::AVSession::HDRFormat::VIDEO_HLG, 1},
    {OHOS::AVSession::HDRFormat::VIDEO_HDR10, 2},
    {OHOS::AVSession::HDRFormat::VIDEO_HDR_VIVID, 3},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_VIVID_DUAL, 4},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_VIVID_SINGLE, 5},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_ISO_DUAL, 6},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_ISO_SINGLE, 7},
};

bool TaiheAVSessionEnum::ToAniEnumHDRFormat(OHOS::AVSession::HDRFormat format, ani_enum_item &aniEnumItem)
{
    auto iter = ANI_HDR_FORMAT_INDEX_MAP.find(format);
    if (iter == ANI_HDR_FORMAT_INDEX_MAP.end()) {
        SLOGE("ToAniEnumHDRFormat unsupport format: %{public}d", static_cast<int32_t>(format));
        return false;
    }
    ani_env *env = taihe::get_env();
    static const std::string enumName = "@ohos.graphics.hdrCapability.hdrCapability.HDRFormat";
    ani_enum aniEnum {};
    if (env == nullptr || env->FindEnum(enumName.c_str(), &aniEnum) != ANI_OK ||
        env->Enum_GetEnumItemByIndex(aniEnum, static_cast<ani_int>(iter->second), &aniEnumItem) != ANI_OK) {
        SLOGE("ToAniEnumHDRFormat create ani enum item fail");
        return false;
    }
    return true;
}
} // namespace ANI::AVSession