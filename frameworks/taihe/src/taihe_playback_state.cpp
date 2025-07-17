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
#define LOG_TAG "TaihePlaybackState"
#endif

#include "taihe_playback_state.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaihePlaybackState::GetterType> TaihePlaybackState::getterMap_ = {
    {"state", GetState},
    {"speed", GetSpeed},
    {"position", GetPosition},
    {"bufferedTime", GetBufferedTime},
    {"loopMode", GetLoopMode},
    {"isFavorite", GetIsFavorite},
    {"activeItemId", GetActiveItemId},
    {"volume", GetVolume},
    {"maxVolume", GetMaxVolume},
    {"muted", GetMuted},
    {"duration", GetDuration},
    {"videoWidth", GetVideoWidth},
    {"videoHeight", GetVideoHeight},
    {"extras", GetExtras},
};

std::map<int32_t, TaihePlaybackState::SetterType> TaihePlaybackState::setterMap_ = {
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_STATE, SetState},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_SPEED, SetSpeed},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_POSITION, SetPosition},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_BUFFERED_TIME, SetBufferedTime},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_LOOP_MODE, SetLoopMode},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE, SetIsFavorite},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_ACTIVE_ITEM_ID, SetActiveItemId},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VOLUME, SetVolume},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_MAX_VOLUME, SetMaxVolume},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_MUTED, SetMuted},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_DURATION, SetDuration},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VIDEO_WIDTH, SetVideoWidth},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VIDEO_HEIGHT, SetVideoHeight},
    {OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_EXTRAS, SetExtras},
};

std::map<std::string, int32_t> TaihePlaybackState::filterMap_ = {
    {"state", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_STATE},
    {"speed", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_SPEED},
    {"position", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_POSITION},
    {"bufferedTime", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_BUFFERED_TIME},
    {"loopMode", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_LOOP_MODE},
    {"isFavorite", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_IS_FAVORITE},
    {"activeItemId", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_ACTIVE_ITEM_ID},
    {"volume", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VOLUME},
    {"maxVolume", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_MAX_VOLUME},
    {"muted", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_MUTED},
    {"duration", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_DURATION},
    {"videoWidth", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VIDEO_WIDTH},
    {"videoHeight", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_VIDEO_HEIGHT},
    {"extras", OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_EXTRAS},
};

int32_t TaihePlaybackState::ConvertFilter(string_view filter,
    OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType &mask)
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

int32_t TaihePlaybackState::ConvertFilter(array<string> filter,
    OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType &mask)
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
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetAVPlaybackState(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVPlaybackState get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVPlaybackState get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetAVPlaybackState(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    auto mask = in.GetMask();
    for (int32_t i = 0; i < OHOS::AVSession::AVPlaybackState::PLAYBACK_KEY_MAX; ++i) {
        if (!mask.test(i)) {
            continue;
        }
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVPlaybackState set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVPlaybackState TaihePlaybackState::CreateUndefinedAVPlaybackState()
{
    AVPlaybackState state {
        .state = optional<PlaybackState>(std::nullopt),
        .speed = optional<double>(std::nullopt),
        .position = optional<PlaybackPosition>(std::nullopt),
        .bufferedTime = optional<int64_t>(std::nullopt),
        .loopMode = optional<LoopMode>(std::nullopt),
        .isFavorite = optional<bool>(std::nullopt),
        .activeItemId = optional<int32_t>(std::nullopt),
        .volume = optional<int32_t>(std::nullopt),
        .maxVolume = optional<int32_t>(std::nullopt),
        .muted = optional<bool>(std::nullopt),
        .duration = optional<int32_t>(std::nullopt),
        .videoWidth = optional<int32_t>(std::nullopt),
        .videoHeight = optional<int32_t>(std::nullopt),
        .extras = optional<uintptr_t>(std::nullopt),
    };
    return state;
}

int32_t TaihePlaybackState::GetState(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.state.has_value() ? in.state.value().get_value() : 0;
    SLOGD("GetState %{public}d", property);
    out.SetState(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetState(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetState %{public}d", in.GetState());
    PlaybackState state = TaiheAVSessionEnum::ToTaihePlaybackState(in.GetState());
    out.state = optional<PlaybackState>(std::in_place_t {}, state);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetSpeed(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    double property = in.speed.has_value() ? in.speed.value() : 1.0;
    SLOGD("GetSpeed %{public}f", property);
    out.SetSpeed(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetSpeed(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetSpeed %{public}f", in.GetSpeed());
    out.speed = optional<double>(std::in_place_t {}, in.GetSpeed());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetPosition(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    if (in.position.has_value()) {
        OHOS::AVSession::AVPlaybackState::Position position = {
            .elapsedTime_ = in.position.value().elapsedTime,
            .updateTime_ = in.position.value().updateTime,
        };
        out.SetPosition(position);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetPosition(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    OHOS::AVSession::AVPlaybackState::Position positionIn = in.GetPosition();
    PlaybackPosition positionOut = {
        .elapsedTime = positionIn.elapsedTime_,
        .updateTime = positionIn.updateTime_,
    };
    out.position = optional<PlaybackPosition>(std::in_place_t {}, positionOut);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetBufferedTime(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int64_t property = in.bufferedTime.has_value() ? in.bufferedTime.value() : 0;
    SLOGD("GetBufferedTime %{public}lld", property);
    out.SetBufferedTime(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetBufferedTime(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetSpeed %{public}lld", in.GetBufferedTime());
    out.bufferedTime = optional<int64_t>(std::in_place_t {}, in.GetBufferedTime());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetLoopMode(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.loopMode.has_value() ? in.loopMode.value().get_value() : 0;
    SLOGD("GetLoopMode %{public}d", property);
    out.SetLoopMode(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetLoopMode(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetLoopMode %{public}d", in.GetLoopMode());
    LoopMode mode = TaiheAVSessionEnum::ToTaiheLoopMode(in.GetLoopMode());
    out.loopMode = optional<LoopMode>(std::in_place_t {}, mode);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetIsFavorite(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    bool property = in.isFavorite.has_value() ? in.isFavorite.value() : false;
    SLOGD("GetIsFavorite %{public}d", property);
    out.SetFavorite(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetIsFavorite(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetIsFavorite %{public}d", in.GetFavorite());
    out.isFavorite = optional<bool>(std::in_place_t {}, in.GetFavorite());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetActiveItemId(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.activeItemId.has_value() ? in.activeItemId.value() : 0;
    SLOGD("GetActiveItemId %{public}d", property);
    out.SetActiveItemId(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetActiveItemId(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetActiveItemId %{public}d", in.GetActiveItemId());
    out.activeItemId = optional<int32_t>(std::in_place_t {}, in.GetActiveItemId());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetVolume(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.volume.has_value() ? in.volume.value() : 0;
    SLOGD("GetVolume %{public}d", property);
    out.SetVolume(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetVolume(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetVolume %{public}d", in.GetVolume());
    out.volume = optional<int32_t>(std::in_place_t {}, in.GetVolume());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetMaxVolume(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.maxVolume.has_value() ? in.maxVolume.value() : 0;
    SLOGD("GetMaxVolume %{public}d", property);
    out.SetMaxVolume(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetMaxVolume(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetVolume %{public}d", in.GetMaxVolume());
    out.maxVolume = optional<int32_t>(std::in_place_t {}, in.GetMaxVolume());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetMuted(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    bool property = in.muted.has_value() ? in.muted.value() : false;
    SLOGD("GetMuted %{public}d", property);
    out.SetMuted(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetMuted(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetMuted %{public}d", in.GetMuted());
    out.muted = optional<bool>(std::in_place_t {}, in.GetMuted());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetDuration(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.duration.has_value() ? in.duration.value() : 0;
    SLOGD("GetDuration %{public}d", property);
    out.SetDuration(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetDuration(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetDuration %{public}d", in.GetDuration());
    out.duration = optional<int32_t>(std::in_place_t {}, in.GetDuration());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetVideoWidth(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.videoWidth.has_value() ? in.videoWidth.value() : 0;
    SLOGD("GetVideoWidth %{public}d", property);
    out.SetVideoWidth(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetVideoWidth(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetVideoWidth %{public}d", in.GetVideoWidth());
    out.videoWidth = optional<int32_t>(std::in_place_t {}, in.GetVideoWidth());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetVideoHeight(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    int32_t property = in.videoHeight.has_value() ? in.videoHeight.value() : 0;
    SLOGD("GetVideoHeight %{public}d", property);
    out.SetVideoHeight(property);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetVideoHeight(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    SLOGD("SetVideoHeight %{public}d", in.GetVideoHeight());
    out.videoHeight = optional<int32_t>(std::in_place_t {}, in.GetVideoHeight());
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::GetExtras(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)
{
    if (in.extras.has_value()) {
        OHOS::AAFwk::WantParams property {};
        int32_t status = TaiheUtils::GetWantParams(in.extras.value(), property);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "GetExtras failed", status);
        out.SetExtras(std::make_shared<OHOS::AAFwk::WantParams>(property));
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaihePlaybackState::SetExtras(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)
{
    std::shared_ptr<OHOS::AAFwk::WantParams> extras = in.GetExtras();
    if (extras == nullptr) {
        SLOGE("Extras is null");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    auto property = TaiheUtils::ToAniWantParams(*extras);
    out.extras = (property == nullptr) ? optional<uintptr_t>(std::nullopt) :
        optional<uintptr_t>(std::in_place_t {}, reinterpret_cast<uintptr_t>(property));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession