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

#ifndef NAPI_CONTROL_COMMAND_H
#define NAPI_CONTROL_COMMAND_H

#include <map>
#include <functional>
#include "napi/native_api.h"
#include "avcontrol_command.h"

namespace OHOS::AVSession {
class NapiControlCommand {
public:
    using GetterType = std::function<napi_status(napi_env, napi_value, AVControlCommand&)>;
    using SetterType = std::function<napi_status(napi_env, AVControlCommand&, napi_value&)>;

    static std::string ConvertCommand(int32_t cmd);
    static int32_t ConvertCommand(const std::string& cmd);
    static std::vector<std::string> ConvertCommands(const std::vector<int32_t>& cmds);

    static napi_status GetValue(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status SetValue(napi_env env, AVControlCommand& in, napi_value& out);

    static napi_status GetNoneParam(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetPlayParam(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetSpeed(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetForwardTime(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetRewindTime(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetSeekTime(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetLoopMode(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetTargetLoopMode(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetAssetId(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetPlayFromAssetId(napi_env env, napi_value in, AVControlCommand& out);
    static napi_status GetPlayWithAssetId(napi_env env, napi_value in, AVControlCommand& out);

    static napi_status SetNoneParam(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetSpeed(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetForwardTime(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetRewindTime(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetSeekTime(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetLoopMode(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetTargetLoopMode(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetAssetId(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetPlayFromAssetId(napi_env env, AVControlCommand& in, napi_value& out);
    static napi_status SetPlayWithAssetId(napi_env env, AVControlCommand& in, napi_value& out);

private:
    static std::map<std::string, std::tuple<GetterType, SetterType, int32_t>> commandMap_;
    static constexpr int GETTER_INDEX = 0;
    static constexpr int SETTER_INDEX = 1;
    static constexpr int ENUM_INDEX = 2;
};
}
#endif // NAPI_CONTROL_COMMAND_H