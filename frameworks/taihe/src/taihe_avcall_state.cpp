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
#define LOG_TAG "TaiheAVCallState"
#endif

#include "taihe_avcall_state.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaiheAVCallState::GetterType> TaiheAVCallState::getterMap_ = {
    {"state", GetCallState},
    {"muted", IsAVCallMuted},
};

std::map<int32_t, TaiheAVCallState::SetterType> TaiheAVCallState::setterMap_ = {
    {OHOS::AVSession::AVCallState::AVCALL_STATE_KEY_STATE, SetCallState},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_KEY_IS_MUTED, SetAVCallMuted},
};

std::map<std::string, int32_t> TaiheAVCallState::filterMap_ = {
    {"state", OHOS::AVSession::AVCallState::AVCALL_STATE_KEY_STATE},
    {"muted", OHOS::AVSession::AVCallState::AVCALL_STATE_KEY_IS_MUTED},
};

int32_t TaiheAVCallState::ConvertFilter(string_view filter, OHOS::AVSession::AVCallState::AVCallStateMaskType &mask)
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

int32_t TaiheAVCallState::ConvertFilter(array<string> filter, OHOS::AVSession::AVCallState::AVCallStateMaskType &mask)
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
    CHECK_RETURN(!mask.none(), "array element invalid.", OHOS::AVSession::ERR_INVALID_PARAM);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallState::GetAVCallState(AVCallState const &in, OHOS::AVSession::AVCallState &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVCallState get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVCallState get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallState::SetAVCallState(const OHOS::AVSession::AVCallState &in, AVCallState &out)
{
    auto mask = in.GetMask();
    for (int32_t i = 0; i < OHOS::AVSession::AVCallState::AVCALL_STATE_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVCallState set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVCallState TaiheAVCallState::CreateUndefinedAVCallState()
{
    AVCallState callState {
        .state = CallState(CallState::key_t::CALL_STATE_IDLE),
        .muted = false,
    };
    return callState;
}

int32_t TaiheAVCallState::GetCallState(AVCallState const &in, OHOS::AVSession::AVCallState &out)
{
    out.SetAVCallState(in.state.get_value());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallState::SetCallState(const OHOS::AVSession::AVCallState &in, AVCallState &out)
{
    out.state = CallState::from_value(in.GetAVCallState());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallState::IsAVCallMuted(AVCallState const &in, OHOS::AVSession::AVCallState &out)
{
    out.SetAVCallMuted(in.muted);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCallState::SetAVCallMuted(const OHOS::AVSession::AVCallState &in, AVCallState &out)
{
    out.muted = in.IsAVCallMuted();
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession