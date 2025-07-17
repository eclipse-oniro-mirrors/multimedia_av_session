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
#define LOG_TAG "TaiheCastControlCommand"
#endif

#include "taihe_cast_control_command.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, std::tuple<TaiheCastControlCommand::GetterType, TaiheCastControlCommand::SetterType, int32_t>>
    TaiheCastControlCommand::commandMap_ = {
    {"play", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY}},
    {"pause", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PAUSE}},
    {"stop", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_STOP}},
    {"playNext", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT}},
    {"playPrevious",
        {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS}},
    {"fastForward",
        {GetForwardTime, SetForwardTime, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD}},
    {"rewind", {GetRewindTime, SetRewindTime, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_REWIND}},
    {"seek", {GetSeekTime, SetSeekTime, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SEEK}},
    {"setVolume", {GetVolume, SetVolume, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME}},
    {"setSpeed", {GetSpeed, SetSpeed, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED}},
    {"setLoopMode", {GetLoopMode, SetLoopMode, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE}},
    {"toggleFavorite",
        {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE}},
    {"toggleMute", {GetNoneParam, SetNoneParam, OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE}},
};

static int32_t GetParameter(const taihe::optional<AVCastParameterType> &in, int32_t &out)
{
    if (in.has_value() && in.value().get_tag() == AVCastParameterType::tag_t::typeInt32) {
        out = in.value().get_typeInt32_ref();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVCastParameterType> ToTaiheParameter(int32_t in)
{
    AVCastParameterType parameter = AVCastParameterType::make_typeInt32(in);
    return taihe::optional<AVCastParameterType>(std::in_place_t {}, parameter);
}

static int32_t GetParameterLoopMode(const taihe::optional<AVCastParameterType> &in, int32_t &out)
{
    if (in.has_value() && in.value().get_tag() == AVCastParameterType::tag_t::typeLoopMode) {
        out = in.value().get_typeLoopMode_ref().get_value();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVCastParameterType> ToTaiheParameterLoopMode(int32_t in)
{
    LoopMode mode = TaiheAVSessionEnum::ToTaiheLoopMode(in);
    AVCastParameterType parameter = AVCastParameterType::make_typeLoopMode(mode);
    return taihe::optional<AVCastParameterType>(std::in_place_t {}, parameter);
}

static int32_t GetParameterPlaybackSpeed(const taihe::optional<AVCastParameterType> &in, int32_t &out)
{
    if (in.has_value() && in.value().get_tag() == AVCastParameterType::tag_t::typePlaybackSpeed) {
        ani_env *env = taihe::get_env();
        CHECK_RETURN(env != nullptr, "env is nullptr", OHOS::AVSession::ERR_INVALID_PARAM);

        ani_enum_item aniEnumItem = reinterpret_cast<ani_enum_item>(in.value().get_typePlaybackSpeed_ref());
        CHECK_RETURN(aniEnumItem != nullptr, "aniEnumItem is nullptr", OHOS::AVSession::ERR_INVALID_PARAM);

        ani_int aniInt = 0;
        CHECK_RETURN(env->EnumItem_GetValue_Int(aniEnumItem, &aniInt) == ANI_OK,
            "GetParameterPlaybackSpeed failed", OHOS::AVSession::ERR_INVALID_PARAM);

        out = static_cast<int32_t>(aniInt);
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::ERR_INVALID_PARAM;
}

static taihe::optional<AVCastParameterType> ToTaiheParameterPlaybackSpeed(int32_t in)
{
    auto undefinedResult = taihe::optional<AVCastParameterType>(std::nullopt);
    ani_env *env = taihe::get_env();
    CHECK_RETURN(env != nullptr, "env is nullptr", undefinedResult);

    ani_enum aniEnum {};
    CHECK_RETURN(env->FindEnum("L@ohos/multimedia/media/media/PlaybackSpeed;", &aniEnum),
        "FindEnum PlaybackSpeed Failed", undefinedResult);

    ani_int enumIndex = static_cast<ani_int>(in);
    ani_enum_item aniEnumItem {};
    CHECK_RETURN(env->Enum_GetEnumItemByIndex(aniEnum, enumIndex, &aniEnumItem),
        "Enum_GetEnumItemByIndex PlaybackSpeed Failed", undefinedResult);

    uintptr_t speed = reinterpret_cast<uintptr_t>(aniEnumItem);
    AVCastParameterType parameter = AVCastParameterType::make_typePlaybackSpeed(speed);
    return taihe::optional<AVCastParameterType>(std::in_place_t {}, parameter);
}

int32_t TaiheCastControlCommand::ConvertCommand(const std::string &cmd)
{
    for (const auto &[key, value] : commandMap_) {
        if (key == cmd) {
            return std::get<ENUM_INDEX>(value);
        }
    }
    return OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_INVALID;
}

std::string TaiheCastControlCommand::ConvertCommand(int32_t cmd)
{
    for (const auto &[key, value] : commandMap_) {
        if (std::get<ENUM_INDEX>(value) == cmd) {
            return key;
        }
    }
    return {};
}

std::vector<std::string> TaiheCastControlCommand::ConvertCommands(const std::vector<int32_t> &cmds)
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

int32_t TaiheCastControlCommand::GetValue(AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
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

int32_t TaiheCastControlCommand::SetValue(OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
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

int32_t TaiheCastControlCommand::GetNoneParam(
    AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    SLOGD("no param need to get");
    (void)(in);
    (void)(out);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetNoneParam(
    OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    SLOGD("no param need to set");
    (void)(in);
    (void)(out);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetForwardTime(
    AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    int32_t forwardTime = 0;
    int32_t status = GetParameter(in.parameter, forwardTime);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGI("get forwardTime failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetForwardTime(forwardTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set forwardTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetForwardTime(
    OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t forwardTime = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetForwardTime(forwardTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get forwardTime failed");

    out.parameter = ToTaiheParameter(forwardTime);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetRewindTime(
    AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    int32_t rewindTime = 0;
    int32_t status = GetParameter(in.parameter, rewindTime);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGI("get rewindTime failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetRewindTime(rewindTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set rewindTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetRewindTime(
    OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t rewindTime = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetRewindTime(rewindTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get rewindTime failed");

    out.parameter = ToTaiheParameter(rewindTime);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetSpeed(AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    int32_t speed = 0;
    int32_t status = GetParameterPlaybackSpeed(in.parameter, speed);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get speed failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSpeed(speed) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set speed failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetSpeed(OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t speed = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetSpeed(speed) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get speed failed");

    out.parameter = ToTaiheParameterPlaybackSpeed(speed);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetSeekTime(
    AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    int32_t seekTime = 0;
    int32_t status = GetParameter(in.parameter, seekTime);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get seekTime failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetSeekTime(seekTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set seekTime failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetSeekTime(
    OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t seekTime = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetSeekTime(seekTime) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get seekTime failed");

    out.parameter = ToTaiheParameter(seekTime);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetVolume(AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
{
    int32_t volume = 0;
    int32_t status = GetParameter(in.parameter, volume);
    if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("get volume failed");
        return status;
    }

    CHECK_AND_RETURN_RET_LOG(out.SetVolume(volume) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "set volume failed");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::SetVolume(OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t volume = 0;
    CHECK_AND_RETURN_RET_LOG(in.GetVolume(volume) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get volume failed");

    out.parameter = ToTaiheParameter(volume);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheCastControlCommand::GetLoopMode(
    AVCastControlCommand const &in, OHOS::AVSession::AVCastControlCommand &out)
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

int32_t TaiheCastControlCommand::SetLoopMode(
    OHOS::AVSession::AVCastControlCommand const &in, AVCastControlCommand &out)
{
    int32_t loopMode = OHOS::AVSession::AVPlaybackState::LOOP_MODE_UNDEFINED;
    CHECK_AND_RETURN_RET_LOG(in.GetLoopMode(loopMode) == OHOS::AVSession::AVSESSION_SUCCESS,
        OHOS::AVSession::ERR_INVALID_PARAM, "get loopMode failed");

    out.parameter = ToTaiheParameterLoopMode(loopMode);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession