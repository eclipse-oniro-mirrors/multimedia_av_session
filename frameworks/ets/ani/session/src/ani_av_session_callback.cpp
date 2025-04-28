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

#include "ani_av_session_callback.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "ani_av_session_utils.h"

namespace OHOS::AVSession {
AniAVSessionCallback::AniAVSessionCallback()
{
    SLOGI("construct AniAVSessionCallback");
    isValid_ = std::make_shared<bool>(true);
}

AniAVSessionCallback::~AniAVSessionCallback()
{
    SLOGI("destroy AniAVSessionCallback");
    *isValid_ = false;
}

void AniAVSessionCallback::HandleEvent(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }

    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGI("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            });
    }
}

template<typename T>
void AniAVSessionCallback::HandleEvent(int32_t event, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }

    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event=%{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                if (!hasFunc) {
                    SLOGE("checkCallbackValid res false for event=%{public}d", event);
                }
                return hasFunc;
            },
            [param](ani_env *env, ani_object object) {
                AniUtils::SetValue(env, param, object);
            });
    }
}

void AniAVSessionCallback::OnPlay()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnPlay");
    HandleEvent(EVENT_PLAY);
}

void AniAVSessionCallback::OnPause()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnPause");
    HandleEvent(EVENT_PAUSE);
}

void AniAVSessionCallback::OnStop()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnStop");
    HandleEvent(EVENT_STOP);
}

void AniAVSessionCallback::OnPlayNext()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnPlayNext");
    HandleEvent(EVENT_PLAY_NEXT);
}

void AniAVSessionCallback::OnPlayPrevious()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnPlayPrevious");
    HandleEvent(EVENT_PLAY_PREVIOUS);
}

void AniAVSessionCallback::OnFastForward(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnFastForward");
    HandleEvent(EVENT_FAST_FORWARD, time);
}

void AniAVSessionCallback::OnRewind(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnRewind");
    HandleEvent(EVENT_REWIND, time);
}

void AniAVSessionCallback::OnSeek(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnSeek");
    HandleEvent(EVENT_SEEK, time);
}

void AniAVSessionCallback::OnSetSpeed(double speed)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnSetSpeed");
    HandleEvent(EVENT_SET_SPEED, speed);
}

void AniAVSessionCallback::OnToggleFavorite(const std::string& assertId)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnToggleFavorite");
    HandleEvent(EVENT_TOGGLE_FAVORITE, assertId);
}

void AniAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnSkipToQueueItem");
    HandleEvent(EVENT_SKIP_TO_QUEUE_ITEM, itemId);
}

void AniAVSessionCallback::OnAVCallAnswer()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnAnswer");
    HandleEvent(EVENT_AVCALL_ANSWER);
}

void AniAVSessionCallback::OnAVCallHangUp()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnHangUp");
    HandleEvent(EVENT_AVCALL_HANG_UP);
}

void AniAVSessionCallback::OnAVCallToggleCallMute()
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnToggleCallMute");
    HandleEvent(EVENT_AVCALL_TOGGLE_CALL_MUTE);
}

void AniAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnPlayFromAssetId");
    HandleEvent(EVENT_PLAY_FROM_ASSETID, assetId);
}

void AniAVSessionCallback::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    AVSESSION_TRACE_SYNC_START("AniAVSessionCallback::OnCastDisplayChange");
    HandleEvent(EVENT_DISPLAY_CHANGE, castDisplayInfo);
}

ani_status AniAVSessionCallback::AddCallback(ani_env *env, int32_t event, ani_ref callback)
{
    SLOGI("Add callback %{public}d", event);
    CHECK_AND_RETURN_RET_LOG(env == nullptr, ANI_ERROR, "env is nullptr");
    std::lock_guard<std::mutex> lockGuard(lock_);
    env_ = env;
    ani_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(ANI_OK == AniUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             ANI_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, ANI_OK, "callback has been registered");
    ani_status status = env->GlobalReference_Create(callback, &ref);
    if (status != ANI_OK) {
        SLOGE("GlobalReference_Create failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<AniAsyncCallback>(env);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return ANI_ERROR;
        }
    }
    callbacks_[event].push_back(ref);
    return ANI_OK;
}
}
