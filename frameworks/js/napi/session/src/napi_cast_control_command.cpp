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

#include "napi_cast_control_command.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
std::map<std::string, std::tuple<NapiCastControlCommand::GetterType, NapiCastControlCommand::SetterType, int32_t>>
    NapiCastControlCommand::commandMap_ = {
    { "play", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_PLAY } },
    { "pause", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_PAUSE } },
    { "stop", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_STOP } },
    { "playNext", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT } },
    { "playPrevious", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS } },
    { "fastForward", { GetForwardTime, SetForwardTime, AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD } },
    { "rewind", { GetRewindTime, SetRewindTime, AVCastControlCommand::CAST_CONTROL_CMD_REWIND } },
    { "seek", { GetSeekTime, SetSeekTime, AVCastControlCommand::CAST_CONTROL_CMD_SEEK } },
    { "setVolume", { GetVolume, SetVolume, AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME } },
    { "setSpeed", { GetSpeed, SetSpeed, AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED } },
    { "setLoopMode", { GetLoopMode, SetLoopMode, AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE } },
    { "toggleFavorite", { GetNoneParam, SetNoneParam, AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE } },
};

int32_t NapiCastControlCommand::ConvertCommand(const std::string& cmd)
{
    for (const auto& [key, value] : commandMap_) {
        if (key == cmd) {
            return std::get<ENUM_INDEX>(value);
        }
    }
    return AVCastControlCommand::CAST_CONTROL_CMD_INVALID;
}

std::string NapiCastControlCommand::ConvertCommand(int32_t cmd)
{
    for (const auto& [key, value] : commandMap_) {
        if (std::get<ENUM_INDEX>(value) == cmd) {
            return key;
        }
    }
    return {};
}

std::vector<std::string> NapiCastControlCommand::ConvertCommands(const std::vector<int32_t>& cmds)
{
    std::vector<std::string> result;
    for (const auto& cmd : cmds) {
        auto stringCmd = ConvertCommand(cmd);
        if (!stringCmd.empty()) {
            result.push_back(stringCmd);
        }
    }
    return result;
}

napi_status NapiCastControlCommand::GetValue(napi_env env, napi_value in, AVCastControlCommand& out)
{
    std::string cmd;
    auto status = NapiUtils::GetNamedProperty(env, in, "command", cmd);
    if (status != napi_ok) {
        SLOGE("get command property failed");
        return status;
    }

    SLOGI("cmd=%{public}s", cmd.c_str());
    auto it = commandMap_.find(cmd);
    if (it == commandMap_.end()) {
        SLOGE("cmd is invalid");
        return napi_invalid_arg;
    }
    if (out.SetCommand(ConvertCommand(cmd)) != AVSESSION_SUCCESS) {
        SLOGE("native set command failed");
        return napi_invalid_arg;
    }
    auto getter = std::get<GETTER_INDEX>(it->second);
    return getter(env, in, out);
}

napi_status NapiCastControlCommand::SetValue(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    auto cmd = ConvertCommand(in.GetCommand());
    napi_value property {};
    status = NapiUtils::SetValue(env, cmd, property);
    CHECK_RETURN(status == napi_ok, "create command property failed", status);
    status = napi_set_named_property(env, out, "command", property);
    CHECK_RETURN(status == napi_ok, "set command property failed", status);

    auto it = commandMap_.find(cmd);
    if (it == commandMap_.end()) {
        SLOGE("cmd is invalid");
        return napi_invalid_arg;
    }

    auto setter = std::get<SETTER_INDEX>(it->second);
    return setter(env, in, out);
}

napi_status NapiCastControlCommand::GetNoneParam(napi_env env, napi_value in, AVCastControlCommand& out)
{
    SLOGD("no param need to get");
    (void)(env);
    (void)(in);
    (void)(out);
    return napi_ok;
}

napi_status NapiCastControlCommand::SetNoneParam(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    SLOGD("no param need to set");
    (void)(env);
    (void)(in);
    (void)(out);
    return napi_ok;
}

napi_status NapiCastControlCommand::GetForwardTime(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t forwardTime {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", forwardTime);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetForwardTime(forwardTime) == AVSESSION_SUCCESS, napi_invalid_arg,
        "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetForwardTime(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t forwardTime {};
    CHECK_AND_RETURN_RET_LOG(in.GetForwardTime(forwardTime) == AVSESSION_SUCCESS, napi_invalid_arg,
        "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, forwardTime, property);
    if (status != napi_ok) {
        SLOGE("create forwardTime property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiCastControlCommand::GetRewindTime(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t rewindTime {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", rewindTime);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetRewindTime(rewindTime) == AVSESSION_SUCCESS, napi_invalid_arg,
        "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetRewindTime(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t rewindTime {};
    CHECK_AND_RETURN_RET_LOG(in.GetRewindTime(rewindTime) == AVSESSION_SUCCESS, napi_invalid_arg,
        "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, rewindTime, property);
    if (status != napi_ok) {
        SLOGE("create rewindTime property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiCastControlCommand::GetSpeed(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t speed {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", speed);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSpeed(speed) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetSpeed(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t speed {};
    CHECK_AND_RETURN_RET_LOG(in.GetSpeed(speed) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, speed, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiCastControlCommand::GetSeekTime(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t seekTime {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", seekTime);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSeekTime(seekTime) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetSeekTime(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t seekTime {};
    CHECK_AND_RETURN_RET_LOG(in.GetSeekTime(seekTime) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, seekTime, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiCastControlCommand::GetVolume(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t volume {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", volume);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetVolume(volume) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetVolume(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t volume {};
    CHECK_AND_RETURN_RET_LOG(in.GetVolume(volume) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, volume, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiCastControlCommand::GetLoopMode(napi_env env, napi_value in, AVCastControlCommand& out)
{
    int32_t loopMode {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", loopMode);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetLoopMode(loopMode) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiCastControlCommand::SetLoopMode(napi_env env, AVCastControlCommand& in, napi_value& out)
{
    int32_t loopMode {};
    CHECK_AND_RETURN_RET_LOG(in.GetLoopMode(loopMode) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, loopMode, property);
    if (status != napi_ok) {
        SLOGE("create loopMode property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}
}
