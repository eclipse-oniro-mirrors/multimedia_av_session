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

#ifndef TAIHE_AVCALL_STATE_H
#define TAIHE_AVCALL_STATE_H

#include <vector>
#include <map>
#include <string>

#include "avcall_state.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVCallState {
public:
    static int32_t ConvertFilter(string_view filter, OHOS::AVSession::AVCallState::AVCallStateMaskType &mask);
    static int32_t ConvertFilter(array<string> filter, OHOS::AVSession::AVCallState::AVCallStateMaskType &mask);

    static int32_t GetAVCallState(AVCallState const &in, OHOS::AVSession::AVCallState &out);
    static int32_t SetAVCallState(const OHOS::AVSession::AVCallState &in, AVCallState &out);
    static AVCallState CreateUndefinedAVCallState();

    using GetterType = std::function<int32_t(AVCallState const &in, OHOS::AVSession::AVCallState &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVCallState &in, AVCallState &out)>;

private:
    static int32_t GetCallState(AVCallState const &in, OHOS::AVSession::AVCallState &out);
    static int32_t SetCallState(const OHOS::AVSession::AVCallState &in, AVCallState &out);

    static int32_t IsAVCallMuted(AVCallState const &in, OHOS::AVSession::AVCallState &out);
    static int32_t SetAVCallMuted(const OHOS::AVSession::AVCallState &in, AVCallState &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::map<std::string, int32_t> filterMap_;
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCALL_STATE_H