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

#include "napi_control_command.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "napi_utils.h"
#include "avmeta_data.h"

namespace OHOS::AVSession {
std::map<std::string, std::tuple<NapiControlCommand::GetterType, NapiControlCommand::SetterType, int32_t>>
    NapiControlCommand::commandMap_ = {
    { "play", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_PLAY } },
    { "pause", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_PAUSE } },
    { "stop", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_STOP } },
    { "playNext", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_PLAY_NEXT } },
    { "playPrevious", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_PLAY_PREVIOUS } },
    { "fastForward", { GetForwardTime, SetForwardTime, AVControlCommand::SESSION_CMD_FAST_FORWARD } },
    { "rewind", { GetRewindTime, SetRewindTime, AVControlCommand::SESSION_CMD_REWIND } },
    { "seek", { GetSeekTime, SetSeekTime, AVControlCommand::SESSION_CMD_SEEK } },
    { "setSpeed", { GetSpeed, SetSpeed, AVControlCommand::SESSION_CMD_SET_SPEED } },
    { "setLoopMode", { GetLoopMode, SetLoopMode, AVControlCommand::SESSION_CMD_SET_LOOP_MODE } },
    { "setTargetLoopMode",
        { GetTargetLoopMode, SetTargetLoopMode, AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE } },
    { "toggleFavorite", { GetAssetId, SetAssetId, AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE } },
    { "playFromAssetId", { GetPlayFromAssetId, SetPlayFromAssetId, AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID } },
    { "playWithAssetId", { GetPlayWithAssetId, SetPlayWithAssetId, AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID } },
    { "answer", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_AVCALL_ANSWER } },
    { "hangUp", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_AVCALL_HANG_UP } },
    { "toggleCallMute", { GetNoneParam, SetNoneParam, AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE } },
};

int32_t NapiControlCommand::ConvertCommand(const std::string& cmd)
{
    for (const auto& [key, value] : commandMap_) {
        if (key == cmd) {
            return std::get<ENUM_INDEX>(value);
        }
    }
    return AVControlCommand::SESSION_CMD_INVALID;
}

std::string NapiControlCommand::ConvertCommand(int32_t cmd)
{
    for (const auto& [key, value] : commandMap_) {
        if (std::get<ENUM_INDEX>(value) == cmd) {
            return key;
        }
    }
    return {};
}

std::vector<std::string> NapiControlCommand::ConvertCommands(const std::vector<int32_t>& cmds)
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

napi_status NapiControlCommand::GetValue(napi_env env, napi_value in, AVControlCommand& out)
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

napi_status NapiControlCommand::SetValue(napi_env env, AVControlCommand& in, napi_value& out)
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

napi_status NapiControlCommand::GetNoneParam(napi_env env, napi_value in, AVControlCommand& out)
{
    SLOGD("no param need to get");
    (void)(env);
    (void)(in);
    (void)(out);
    return napi_ok;
}

napi_status NapiControlCommand::SetNoneParam(napi_env env, AVControlCommand& in, napi_value& out)
{
    SLOGD("no param need to set");
    (void)(env);
    (void)(in);
    (void)(out);
    return napi_ok;
}

napi_status NapiControlCommand::GetSpeed(napi_env env, napi_value in, AVControlCommand& out)
{
    double speed {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", speed);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSpeed(speed) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetSpeed(napi_env env, AVControlCommand& in, napi_value& out)
{
    double speed {};
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

napi_status NapiControlCommand::GetForwardTime(napi_env env, napi_value in, AVControlCommand& out)
{
    int64_t time {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", time);
    if (status != napi_ok) {
        SLOGI("get ForwardTime parameter failed but set default");
        time = AVMetaData::SECONDS_15;
        status = napi_ok;
    }

    SLOGD("GetForwardTime with time %{public}jd", static_cast<int64_t>(time));
    CHECK_AND_RETURN_RET_LOG(out.SetForwardTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetForwardTime(napi_env env, AVControlCommand& in, napi_value& out)
{
    int64_t time {};
    CHECK_AND_RETURN_RET_LOG(in.GetForwardTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");
    SLOGD("SetForwardTime with time %{public}jd", static_cast<int64_t>(time));

    napi_value property {};
    auto status = NapiUtils::SetValue(env, time, property);
    if (status != napi_ok) {
        SLOGE("create ForwardTime property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetRewindTime(napi_env env, napi_value in, AVControlCommand& out)
{
    int64_t time {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", time);
    if (status != napi_ok) {
        SLOGI("get RewindTime parameter failed but set default");
        time = AVMetaData::SECONDS_15;
        status = napi_ok;
    }

    SLOGD("GetRewindTime with time %{public}jd", static_cast<int64_t>(time));
    CHECK_AND_RETURN_RET_LOG(out.SetRewindTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetRewindTime(napi_env env, AVControlCommand& in, napi_value& out)
{
    int64_t time {};
    CHECK_AND_RETURN_RET_LOG(in.GetRewindTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");
    SLOGD("SetRewindTime with time %{public}jd", static_cast<int64_t>(time));

    napi_value property {};
    auto status = NapiUtils::SetValue(env, time, property);
    if (status != napi_ok) {
        SLOGE("create RewindTime property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetSeekTime(napi_env env, napi_value in, AVControlCommand& out)
{
    int64_t time {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", time);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSeekTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetSeekTime(napi_env env, AVControlCommand& in, napi_value& out)
{
    int64_t time {};
    CHECK_AND_RETURN_RET_LOG(in.GetSeekTime(time) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, time, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetLoopMode(napi_env env, napi_value in, AVControlCommand& out)
{
    int32_t loopMode {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", loopMode);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        loopMode = AVPlaybackState::LOOP_MODE_UNDEFINED;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetLoopMode(loopMode) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetLoopMode(napi_env env, AVControlCommand& in, napi_value& out)
{
    int32_t loopMode {};
    CHECK_AND_RETURN_RET_LOG(in.GetLoopMode(loopMode) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, loopMode, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetTargetLoopMode(napi_env env, napi_value in, AVControlCommand& out)
{
    int32_t targetLoopMode {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", targetLoopMode);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        targetLoopMode = AVPlaybackState::LOOP_MODE_UNDEFINED;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetTargetLoopMode(targetLoopMode) == AVSESSION_SUCCESS,
        napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetTargetLoopMode(napi_env env, AVControlCommand& in, napi_value& out)
{
    int32_t targetLoopMode {};
    CHECK_AND_RETURN_RET_LOG(in.GetTargetLoopMode(targetLoopMode) == AVSESSION_SUCCESS,
        napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, targetLoopMode, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetAssetId(napi_env env, napi_value in, AVControlCommand& out)
{
    std::string assetId;
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", assetId);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetAssetId(assetId) == AVSESSION_SUCCESS, napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetAssetId(napi_env env, AVControlCommand& in, napi_value& out)
{
    std::string assetId;
    CHECK_AND_RETURN_RET_LOG(in.GetAssetId(assetId) == AVSESSION_SUCCESS, napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, assetId, property);
    if (status != napi_ok) {
        SLOGE("create speed property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetPlayFromAssetId(napi_env env, napi_value in, AVControlCommand& out)
{
    int64_t playFromAssetId {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", playFromAssetId);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        playFromAssetId = 0;
        status = napi_ok;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetPlayFromAssetId(playFromAssetId) == AVSESSION_SUCCESS,
        napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetPlayFromAssetId(napi_env env, AVControlCommand& in, napi_value& out)
{
    int64_t playFromAssetId {};
    CHECK_AND_RETURN_RET_LOG(in.GetPlayFromAssetId(playFromAssetId) == AVSESSION_SUCCESS,
        napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, playFromAssetId, property);
    if (status != napi_ok) {
        SLOGE("create playFromAssetId property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}

napi_status NapiControlCommand::GetPlayWithAssetId(napi_env env, napi_value in, AVControlCommand& out)
{
    std::string playWithAssetId {};
    auto status = NapiUtils::GetNamedProperty(env, in, "parameter", playWithAssetId);
    if (status != napi_ok) {
        SLOGE("get parameter failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetPlayWithAssetId(playWithAssetId) == AVSESSION_SUCCESS,
        napi_invalid_arg, "set parameter failed");
    return status;
}

napi_status NapiControlCommand::SetPlayWithAssetId(napi_env env, AVControlCommand& in, napi_value& out)
{
    std::string playWithAssetId {};
    CHECK_AND_RETURN_RET_LOG(in.GetPlayWithAssetId(playWithAssetId) == AVSESSION_SUCCESS,
        napi_invalid_arg, "get parameter failed");

    napi_value property {};
    auto status = NapiUtils::SetValue(env, playWithAssetId, property);
    if (status != napi_ok) {
        SLOGE("create playWithAssetId property failed");
        return status;
    }

    status = napi_set_named_property(env, out, "parameter", property);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "set parameter property failed");
    return status;
}
}
