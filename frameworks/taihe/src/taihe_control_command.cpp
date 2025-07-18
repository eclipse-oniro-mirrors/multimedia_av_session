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
#define LOG_TAG "TaiheControlCommand"
#endif

#include "taihe_control_command.h"

#include "avmeta_data.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, std::tuple<TaiheControlCommand::GetterType, TaiheControlCommand::SetterType, int32_t>>
    TaiheControlCommand::commandMap_ = {
    {"play", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY}},
    {"pause", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_PAUSE}},
    {"stop", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_STOP}},
    {"playNext", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_NEXT}},
    {"playPrevious", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_PREVIOUS}},
    {"fastForward", {GetForwardTime, SetForwardTime, OHOS::AVSession::AVControlCommand::SESSION_CMD_FAST_FORWARD}},
    {"rewind", {GetRewindTime, SetRewindTime, OHOS::AVSession::AVControlCommand::SESSION_CMD_REWIND}},
    {"seek", {GetSeekTime, SetSeekTime, OHOS::AVSession::AVControlCommand::SESSION_CMD_SEEK}},
    {"setSpeed", {GetSpeed, SetSpeed, OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_SPEED}},
    {"setLoopMode", {GetLoopMode, SetLoopMode, OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_LOOP_MODE}},
    {"setTargetLoopMode",
        {GetTargetLoopMode, SetTargetLoopMode, OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE}},
    {"toggleFavorite", {GetAssetId, SetAssetId, OHOS::AVSession::AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE}},
    {"playFromAssetId",
        {GetPlayFromAssetId, SetPlayFromAssetId, OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID}},
    {"answer", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_ANSWER}},
    {"hangUp", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_HANG_UP}},
    {"toggleCallMute",
        {GetNoneParam, SetNoneParam, OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE}},
};

static int32_t GetParameter(const taihe::optional<AVControlParameterType> &in, int64_t &out)
{
    if (in.has_value() && in.value().get_tag() == AVControlParameterType::tag_t::typeDouble) {
        out = static_cast<int64_t>(in.value().get_typeDouble_ref());
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVControlParameterType> ToTaiheParameter(int64_t in)
{
    AVControlParameterType parameter = AVControlParameterType::make_typeDouble(static_cast<double>(in));
    return taihe::optional<AVControlParameterType>(std::in_place_t {}, parameter);
}

static int32_t GetParameter(const taihe::optional<AVControlParameterType> &in, double &out)
{
    if (in.has_value() && in.value().get_tag() == AVControlParameterType::tag_t::typeDouble) {
        out = in.value().get_typeDouble_ref();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVControlParameterType> ToTaiheParameter(double in)
{
    AVControlParameterType parameter = AVControlParameterType::make_typeDouble(in);
    return taihe::optional<AVControlParameterType>(std::in_place_t {}, parameter);
}

static int32_t GetParameter(const taihe::optional<AVControlParameterType> &in, std::string &out)
{
    if (in.has_value() && in.value().get_tag() == AVControlParameterType::tag_t::typeString) {
        out = std::string(in.value().get_typeString_ref());
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVControlParameterType> ToTaiheParameter(const std::string &in)
{
    AVControlParameterType parameter = AVControlParameterType::make_typeString(in);
    return taihe::optional<AVControlParameterType>(std::in_place_t {}, parameter);
}

static int32_t GetParameterLoopMode(const taihe::optional<AVControlParameterType> &in, int32_t &out)
{
    if (in.has_value() && in.value().get_tag() == AVControlParameterType::tag_t::typeLoopMode) {
        out = in.value().get_typeLoopMode_ref().get_value();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVControlParameterType> ToTaiheParameterLoopMode(int32_t in)
{
    LoopMode mode = LoopMode::from_value(in);
    AVControlParameterType parameter = AVControlParameterType::make_typeLoopMode(mode);
    return taihe::optional<AVControlParameterType>(std::in_place_t {}, parameter);
}

int32_t TaiheControlCommand::ConvertCommand(const std::string &cmd)
{
    for (const auto &[key, value] : commandMap_) {
        if (key == cmd) {
            return std::get<ENUM_INDEX>(value);
        }
    }
    return OHOS::AVSession::AVControlCommand::SESSION_CMD_INVALID;
}

std::string TaiheControlCommand::ConvertCommand(int32_t cmd)
{
    for (const auto &[key, value] : commandMap_) {
        if (std::get<ENUM_INDEX>(value) == cmd) {
            return key;
        }
    }
    return {};
}

std::vector<std::string> TaiheControlCommand::ConvertCommands(const std::vector<int32_t> &cmds)
{
    std::vector<std::string> result;
    for (const auto &cmd : cmds) {
        auto stringCmd = ConvertCommand(cmd);
        if (!stringCmd.empty()) {
            result.push_back(stringCmd);
        }
    }
    return result;
}

int32_t TaiheControlCommand::GetValue(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    std::string cmd;
    int32_t status = TaiheUtils::GetString(in.command, cmd);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get command property failed");
        return status;
    }

    SLOGI("cmd=%{public}s", cmd.c_str());
    auto it = commandMap_.find(cmd);
    if (it == commandMap_.end()) {
        SLOGE("cmd is invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    if (out.SetCommand(ConvertCommand(cmd)) != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("native set command failed");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    auto getter = std::get<GETTER_INDEX>(it->second);
    return getter(in, out);
}

int32_t TaiheControlCommand::SetValue(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    std::string cmd = ConvertCommand(in.GetCommand());
    out.command = taihe::string(cmd);

    auto it = commandMap_.find(cmd);
    if (it == commandMap_.end()) {
        SLOGE("cmd is invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    auto setter = std::get<SETTER_INDEX>(it->second);
    return setter(in, out);
}

int32_t TaiheControlCommand::GetNoneParam(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    SLOGD("no param need to get");
    (void)(in);
    (void)(out);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetNoneParam(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    SLOGD("no param need to set");
    (void)(in);
    (void)(out);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetSpeed(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    double speed = 0;
    int32_t status = GetParameter(in.parameter, speed);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get speed failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSpeed(speed) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set speed failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetSpeed(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    double speed = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetSpeed(speed) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get speed failed");

    out.parameter = ToTaiheParameter(speed);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetForwardTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int64_t time = 0;
    int32_t status = GetParameter(in.parameter, time);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGI("get ForwardTime failed but set default");
        time = OHOS::AVSession::AVMetaData::SECONDS_15;
    }

    SLOGD("GetForwardTime with time %{public}jd", static_cast<int64_t>(time));
    CHECK_AND_RETURN_RET_LOG(out.SetForwardTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set ForwardTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetForwardTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int64_t time = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetForwardTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get ForwardTime failed");
    SLOGD("SetForwardTime with time %{public}jd", static_cast<int64_t>(time));

    out.parameter = ToTaiheParameter(time);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetRewindTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int64_t time = 0;
    int32_t status = GetParameter(in.parameter, time);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGI("get RewindTime failed but set default");
        time = OHOS::AVSession::AVMetaData::SECONDS_15;
    }

    SLOGD("GetRewindTime with time %{public}jd", static_cast<int64_t>(time));
    CHECK_AND_RETURN_RET_LOG(out.SetRewindTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set RewindTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetRewindTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int64_t time = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetRewindTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get RewindTime failed");
    SLOGD("SetRewindTime with time %{public}jd", static_cast<int64_t>(time));

    out.parameter = ToTaiheParameter(time);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetSeekTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int64_t time = 0;
    int32_t status = GetParameter(in.parameter, time);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get SeekTime failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSeekTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set SeekTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetSeekTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int64_t time = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetSeekTime(time) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get SeekTime failed");

    out.parameter = ToTaiheParameter(time);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetLoopMode(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int32_t loopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    int32_t status = GetParameterLoopMode(in.parameter, loopMode);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get loopMode failed");
        loopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetLoopMode(loopMode) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set loopMode failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetLoopMode(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int32_t loopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    CHECK_AND_RETURN_RET_LOG(in.GetLoopMode(loopMode) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get loopMode failed");

    out.parameter = ToTaiheParameterLoopMode(loopMode);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetTargetLoopMode(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int32_t targetLoopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    int32_t status = GetParameterLoopMode(in.parameter, targetLoopMode);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get targetLoopMode failed");
        targetLoopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetTargetLoopMode(targetLoopMode) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set targetLoopMode failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetTargetLoopMode(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int32_t targetLoopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    CHECK_AND_RETURN_RET_LOG(in.GetTargetLoopMode(targetLoopMode) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get targetLoopMode failed");

    out.parameter = ToTaiheParameterLoopMode(targetLoopMode);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetAssetId(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    std::string assetId;
    int32_t status = GetParameter(in.parameter, assetId);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get assetId failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetAssetId(assetId) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set assetId failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetAssetId(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    std::string assetId;
    CHECK_AND_RETURN_RET_LOG(in.GetAssetId(assetId) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get assetId failed");

    out.parameter = ToTaiheParameter(assetId);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::GetPlayFromAssetId(AVControlCommand in, OHOS::AVSession::AVControlCommand &out)
{
    int64_t playFromAssetId = 0;
    int32_t status = GetParameter(in.parameter, playFromAssetId);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get playFromAssetId failed");
        playFromAssetId = 0;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetPlayFromAssetId(playFromAssetId) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set playFromAssetId failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheControlCommand::SetPlayFromAssetId(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out)
{
    int64_t playFromAssetId = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetPlayFromAssetId(playFromAssetId) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get playFromAssetId failed");

    out.parameter = ToTaiheParameter(playFromAssetId);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession