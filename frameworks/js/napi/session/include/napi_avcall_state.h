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

#ifndef OHOS_NAPI_AVCALL_STATE_H
#define OHOS_NAPI_AVCALL_STATE_H

#include <vector>
#include <map>
#include <string>
#include "avcall_state.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiAVCallState {
public:
    static napi_status  ConvertFilter(napi_env env, napi_value filter, AVCallState::AVCallStateMaskType& mask);

    static napi_status GetValue(napi_env env, napi_value in, AVCallState& out);
    static napi_status SetValue(napi_env env, const AVCallState& in, napi_value& out);

    using GetterType = std::function<napi_status(napi_env, napi_value in, AVCallState& out)>;
    using SetterType = std::function<napi_status(napi_env env, const AVCallState& in, napi_value& out)>;

private:
    static napi_status GetAVCallState(napi_env env, napi_value in, AVCallState& out);
    static napi_status SetAVCallState(napi_env env, const AVCallState& in, napi_value& out);

    static napi_status IsAVCallMuted(napi_env env, napi_value in, AVCallState& out);
    static napi_status SetAVCallMuted(napi_env env, const AVCallState& in, napi_value& out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::map<std::string, int32_t> filterMap_;
};
}
#endif // OHOS_NAPI_AVCALL_STATE_H
