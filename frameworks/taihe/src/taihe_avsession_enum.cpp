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
#ifndef LOG_TAG
#define LOG_TAG "TaiheAVSessionEnum"
#endif

#include "taihe_avsession_enum.h"

#include "avsession_log.h"

namespace ANI::AVSession {

static const std::map<OHOS::AVSession::HDRFormat, int32_t> ANI_HDR_FORMAT_INDEX_MAP = {
    {OHOS::AVSession::HDRFormat::NONE, 0},
    {OHOS::AVSession::HDRFormat::VIDEO_HLG, 1},
    {OHOS::AVSession::HDRFormat::VIDEO_HDR10, 2},
    {OHOS::AVSession::HDRFormat::VIDEO_HDR_VIVID, 3},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_VIVID_DUAL, 4},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_VIVID_SINGLE, 5},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_ISO_DUAL, 6},
    {OHOS::AVSession::HDRFormat::IMAGE_HDR_ISO_SINGLE, 7},
};

static const std::map<int32_t, LoopMode> LOOP_MODE_TAIHE_MAP = {
    {OHOS::AVSession::AVPlaybackState::LOOP_MODE_SEQUENCE, LoopMode::key_t::LOOP_MODE_SEQUENCE},
    {OHOS::AVSession::AVPlaybackState::LOOP_MODE_SINGLE, LoopMode::key_t::LOOP_MODE_SINGLE},
    {OHOS::AVSession::AVPlaybackState::LOOP_MODE_LIST, LoopMode::key_t::LOOP_MODE_LIST},
    {OHOS::AVSession::AVPlaybackState::LOOP_MODE_SHUFFLE, LoopMode::key_t::LOOP_MODE_SHUFFLE},
    {OHOS::AVSession::AVPlaybackState::LOOP_MODE_CUSTOM, LoopMode::key_t::LOOP_MODE_CUSTOM},
};

static const std::map<int32_t, AVCastCategory> AV_CAST_CATEGORY_TAIHE_MAP = {
    {OHOS::AVSession::AVCastCategory::CATEGORY_LOCAL, AVCastCategory::key_t::CATEGORY_LOCAL},
    {OHOS::AVSession::AVCastCategory::CATEGORY_REMOTE, AVCastCategory::key_t::CATEGORY_REMOTE},
};

static const std::map<int32_t, DeviceType> DEVICE_TYPE_TAIHE_MAP = {
    {OHOS::AVSession::DeviceType::DEVICE_TYPE_LOCAL, DeviceType::key_t::DEVICE_TYPE_LOCAL},
    {OHOS::AVSession::DeviceType::DEVICE_TYPE_TV, DeviceType::key_t::DEVICE_TYPE_TV},
    {OHOS::AVSession::DeviceType::DEVICE_TYPE_SPEAKER, DeviceType::key_t::DEVICE_TYPE_SMART_SPEAKER},
    {OHOS::AVSession::DeviceType::DEVICE_TYPE_BLUETOOTH, DeviceType::key_t::DEVICE_TYPE_BLUETOOTH},
};

static const std::map<int32_t, SkipIntervals> SKIP_INTERVALS_TAIHE_MAP = {
    {TaiheAVSessionEnum::TaiheAVSkipIntervals::SECONDS_10, SkipIntervals::key_t::SECONDS_10},
    {TaiheAVSessionEnum::TaiheAVSkipIntervals::SECONDS_15, SkipIntervals::key_t::SECONDS_15},
    {TaiheAVSessionEnum::TaiheAVSkipIntervals::SECONDS_30, SkipIntervals::key_t::SECONDS_30},
};

static const std::map<int32_t, PlaybackState> PLAYBACK_STATE_TAIHE_MAP = {
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_INITIAL, PlaybackState::key_t::PLAYBACK_STATE_INITIAL},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_PREPARE, PlaybackState::key_t::PLAYBACK_STATE_PREPARE},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_PLAY, PlaybackState::key_t::PLAYBACK_STATE_PLAY},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_PAUSE, PlaybackState::key_t::PLAYBACK_STATE_PAUSE},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_FAST_FORWARD, PlaybackState::key_t::PLAYBACK_STATE_FAST_FORWARD},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_REWIND, PlaybackState::key_t::PLAYBACK_STATE_REWIND},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_STOP, PlaybackState::key_t::PLAYBACK_STATE_STOP},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_COMPLETED, PlaybackState::key_t::PLAYBACK_STATE_COMPLETED},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_RELEASED, PlaybackState::key_t::PLAYBACK_STATE_RELEASED},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_ERROR, PlaybackState::key_t::PLAYBACK_STATE_ERROR},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_IDLE, PlaybackState::key_t::PLAYBACK_STATE_IDLE},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_STATE_BUFFERING, PlaybackState::key_t::PLAYBACK_STATE_BUFFERING},
};

static const std::map<OHOS::AVSession::CastDisplayState, CastDisplayState> CAST_DISPLAY_STATE_TAIHE_MAP = {
    {OHOS::AVSession::CastDisplayState::STATE_OFF, CastDisplayState::key_t::STATE_OFF},
    {OHOS::AVSession::CastDisplayState::STATE_ON, CastDisplayState::key_t::STATE_ON},
};

static const std::map<int32_t, CallState> CALL_STATE_TAIHE_MAP = {
    {OHOS::AVSession::AVCallState::AVCALL_STATE_IDLE, CallState::key_t::CALL_STATE_IDLE},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_INCOMING, CallState::key_t::CALL_STATE_INCOMING},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_ACTIVE, CallState::key_t::CALL_STATE_ACTIVE},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_DIALING, CallState::key_t::CALL_STATE_DIALING},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_WAITING, CallState::key_t::CALL_STATE_WAITING},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_HOLDING, CallState::key_t::CALL_STATE_HOLDING},
    {OHOS::AVSession::AVCallState::AVCALL_STATE_DISCONNECTING, CallState::key_t::CALL_STATE_DISCONNECTING},
};

static const std::map<int32_t, ConnectionState> CONNECTION_STATE_TAIHE_MAP = {
    {OHOS::AVSession::ConnectionState::STATE_CONNECTING, ConnectionState::key_t::STATE_CONNECTING},
    {OHOS::AVSession::ConnectionState::STATE_CONNECTED, ConnectionState::key_t::STATE_CONNECTED},
    {OHOS::AVSession::ConnectionState::STATE_DISCONNECTED, ConnectionState::key_t::STATE_DISCONNECTED},
};

static const std::map<int32_t, DeviceLogEventCode> DEVICE_LOG_EVENT_CODE_TAIHE_MAP = {
    {OHOS::AVSession::DeviceLogEventCode::DEVICE_LOG_FULL, DeviceLogEventCode::key_t::DEVICE_LOG_FULL},
    {OHOS::AVSession::DeviceLogEventCode::DEVICE_LOG_EXCEPTION, DeviceLogEventCode::key_t::DEVICE_LOG_EXCEPTION},
};

static const std::map<DistributedSessionType, OHOS::AVSession::DistributedSessionType>
    DISTRIBUTED_SESSION_TYPE_TAIHE_MAP = {
    {DistributedSessionType::key_t::TYPE_SESSION_REMOTE, OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE},
    {DistributedSessionType::key_t::TYPE_SESSION_MIGRATE_IN,
        OHOS::AVSession::DistributedSessionType::TYPE_SESSION_MIGRATE_IN},
    {DistributedSessionType::key_t::TYPE_SESSION_MIGRATE_OUT,
        OHOS::AVSession::DistributedSessionType::TYPE_SESSION_MIGRATE_OUT},
};

bool TaiheAVSessionEnum::ToAniEnumHDRFormat(OHOS::AVSession::HDRFormat format, ani_enum_item &aniEnumItem)
{
    auto iter = ANI_HDR_FORMAT_INDEX_MAP.find(format);
    if (iter == ANI_HDR_FORMAT_INDEX_MAP.end()) {
        SLOGE("ToAniEnumHDRFormat unsupport format: %{public}d", static_cast<int32_t>(format));
        return false;
    }
    ani_env *env = taihe::get_env();
    static const std::string enumName = "L@ohos/graphics/hdrCapability/hdrCapability/HDRFormat;";
    ani_enum aniEnum {};
    if (env == nullptr || env->FindEnum(enumName.c_str(), &aniEnum) != ANI_OK ||
        env->Enum_GetEnumItemByIndex(aniEnum, static_cast<ani_int>(iter->second), &aniEnumItem) != ANI_OK) {
        SLOGE("ToAniEnumHDRFormat create ani enum item fail");
        return false;
    }
    return true;
}

LoopMode TaiheAVSessionEnum::ToTaiheLoopMode(int32_t mode)
{
    auto iter = LOOP_MODE_TAIHE_MAP.find(mode);
    if (iter == LOOP_MODE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheLoopMode invalid mode: %{public}d", static_cast<int32_t>(mode));
        return LoopMode::key_t::LOOP_MODE_SEQUENCE;
    }
    return iter->second;
}

AVCastCategory TaiheAVSessionEnum::ToTaiheAVCastCategory(int32_t category)
{
    auto iter = AV_CAST_CATEGORY_TAIHE_MAP.find(category);
    if (iter == AV_CAST_CATEGORY_TAIHE_MAP.end()) {
        SLOGW("ToTaiheAVCastCategory invalid category: %{public}d", static_cast<int32_t>(category));
        return AVCastCategory::key_t::CATEGORY_LOCAL;
    }
    return iter->second;
}

DeviceType TaiheAVSessionEnum::ToTaiheDeviceType(int32_t type)
{
    auto iter = DEVICE_TYPE_TAIHE_MAP.find(type);
    if (iter == DEVICE_TYPE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheDeviceType invalid type: %{public}d", static_cast<int32_t>(type));
        return DeviceType::key_t::DEVICE_TYPE_LOCAL;
    }
    return iter->second;
}

SkipIntervals TaiheAVSessionEnum::ToTaiheSkipIntervals(int32_t intervals)
{
    auto iter = SKIP_INTERVALS_TAIHE_MAP.find(intervals);
    if (iter == SKIP_INTERVALS_TAIHE_MAP.end()) {
        SLOGW("ToTaiheSkipIntervals invalid intervals: %{public}d", static_cast<int32_t>(intervals));
        return SkipIntervals::key_t::SECONDS_10;
    }
    return iter->second;
}

PlaybackState TaiheAVSessionEnum::ToTaihePlaybackState(int32_t state)
{
    auto iter = PLAYBACK_STATE_TAIHE_MAP.find(state);
    if (iter == PLAYBACK_STATE_TAIHE_MAP.end()) {
        SLOGW("ToTaihePlaybackState invalid state: %{public}d", static_cast<int32_t>(state));
        return PlaybackState::key_t::PLAYBACK_STATE_ERROR;
    }
    return iter->second;
}

CastDisplayState TaiheAVSessionEnum::ToTaiheCastDisplayState(OHOS::AVSession::CastDisplayState state)
{
    auto iter = CAST_DISPLAY_STATE_TAIHE_MAP.find(state);
    if (iter == CAST_DISPLAY_STATE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheCastDisplayState invalid state: %{public}d", static_cast<int32_t>(state));
        return CastDisplayState::key_t::STATE_OFF;
    }
    return iter->second;
}

CallState TaiheAVSessionEnum::ToTaiheCallState(int32_t state)
{
    auto iter = CALL_STATE_TAIHE_MAP.find(state);
    if (iter == CALL_STATE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheAVCallState invalid state: %{public}d", static_cast<int32_t>(state));
        return CallState::key_t::CALL_STATE_IDLE;
    }
    return iter->second;
}

ConnectionState TaiheAVSessionEnum::ToTaiheConnectionState(int32_t state)
{
    auto iter = CONNECTION_STATE_TAIHE_MAP.find(state);
    if (iter == CONNECTION_STATE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheConnectionState invalid state: %{public}d", static_cast<int32_t>(state));
        return ConnectionState::key_t::STATE_DISCONNECTED;
    }
    return iter->second;
}

DeviceLogEventCode TaiheAVSessionEnum::ToTaiheDeviceLogEventCode(int32_t eventId)
{
    auto iter = DEVICE_LOG_EVENT_CODE_TAIHE_MAP.find(eventId);
    if (iter == DEVICE_LOG_EVENT_CODE_TAIHE_MAP.end()) {
        SLOGW("ToTaiheDeviceLogEventCode invalid eventId: %{public}d", static_cast<int32_t>(eventId));
        return DeviceLogEventCode::key_t::DEVICE_LOG_EXCEPTION;
    }
    return iter->second;
}

OHOS::AVSession::DistributedSessionType TaiheAVSessionEnum::ToDistributedSessionType(DistributedSessionType type)
{
    auto iter = DISTRIBUTED_SESSION_TYPE_TAIHE_MAP.find(type);
    if (iter == DISTRIBUTED_SESSION_TYPE_TAIHE_MAP.end()) {
        SLOGW("ToDistributedSessionType invalid type: %{public}d", static_cast<int32_t>(type));
        return OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE;
    }
    return iter->second;
}
} // namespace ANI::AVSession