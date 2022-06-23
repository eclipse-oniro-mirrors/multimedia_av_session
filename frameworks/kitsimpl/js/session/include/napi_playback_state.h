/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_PLAYBACK_STATE_H
#define OHOS_NAPI_PLAYBACK_STATE_H

#include <vector>
#include <map>
#include <string>
#include "avplayback_state.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiPlaybackState {
public:
    static AVPlaybackState::PlaybackStateMaskType ConvertFilter(const std::vector<std::string>& filter);

    static napi_status GetValue(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetValue(napi_env env, const AVPlaybackState& in, napi_value& out);

    using GetterType = std::function<napi_status(napi_env, napi_value in, AVPlaybackState& out)>;
    using SetterType = std::function<napi_status(napi_env env, const AVPlaybackState& in, napi_value& out)>;

private:
    static napi_status GetState(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetState(napi_env env, const AVPlaybackState& in, napi_value& out);

    static napi_status GetSpeed(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetSpeed(napi_env env, const AVPlaybackState& in, napi_value& out);

    static napi_status GetPosition(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetPosition(napi_env env, const AVPlaybackState& in, napi_value& out);

    static napi_status GetBufferedTime(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetBufferedTime(napi_env env, const AVPlaybackState& in, napi_value& out);

    static napi_status GetLoopMode(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetLoopMode(napi_env env, const AVPlaybackState& in, napi_value& out);

    static napi_status GetIsFavorite(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetIsFavorite(napi_env env, const AVPlaybackState& in, napi_value& out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::map<std::string, int32_t> filterMap_;
};
}
#endif // OHOS_NAPI_PLAYBACK_STATE_H