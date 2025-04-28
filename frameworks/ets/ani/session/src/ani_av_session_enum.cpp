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

#include "ani_av_session_enum.h"
#include "ani_class_name.h"
#include "ani_av_session_utils.h"

namespace OHOS::AVSession {
static const std::map<CastDisplayState, int32_t> ANI_CASTDISPLAYSTATE_INDEX_MAP = {
    {CastDisplayState::STATE_OFF, 0},
    {CastDisplayState::STATE_ON, 1},
};

ani_status AVSessionEnumAni::ToAniEnum(ani_env *env, CastDisplayState value, ani_enum_item &aniEnumItem)
{
    CHECK_AND_RETURN_RET_LOG(env != nullptr, ANI_INVALID_ARGS, "Invalid env");

    auto it = ANI_CASTDISPLAYSTATE_INDEX_MAP.find(value);
    CHECK_AND_RETURN_RET_LOG(it != ANI_CASTDISPLAYSTATE_INDEX_MAP.end(),
        ANI_INVALID_ARGS, "Unsupport enum: %{public}d", value);
    ani_int enumIndex = static_cast<ani_int>(it->second);

    ani_enum aniEnum {};
    ani_status status = env->FindEnum(ANI_CLASS_AV_SESSION_HANDLE.c_str(), &aniEnum);
    if (status != ANI_OK) {
        SLOGE("Find Enum Fail");
        return status;
    }
    status = env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem);
    if (status != ANI_OK) {
        SLOGE("Find Enum item Fail");
        return status;
    }
    return ANI_OK;
}
}
