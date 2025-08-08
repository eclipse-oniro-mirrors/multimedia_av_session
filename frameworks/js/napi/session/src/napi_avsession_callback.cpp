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

#include "napi_avsession_callback.h"
#include "avsession_log.h"
#include "napi_utils.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
NapiAVSessionCallback::NapiAVSessionCallback()
{
    SLOGI("construct NapiAVSessionCallback");
    isValid_ = std::make_shared<bool>(true);
}

NapiAVSessionCallback::~NapiAVSessionCallback()
{
    SLOGI("destroy NapiAVSessionCallback");
    *isValid_ = false;
}

void NapiAVSessionCallback::HandleEvent(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("send control command %{public}d to session with callback size %{public}d",
        event, static_cast<int>(callbacks_[event].size()));
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
void NapiAVSessionCallback::HandleEvent(int32_t event, const T& param)
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
            [param](napi_env env, int& argc, napi_value* argv) {
                argc = NapiUtils::ARGC_ONE;
                NapiUtils::SetValue(env, param, *argv);
            });
    }
}

template<typename T>
void NapiAVSessionCallback::HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("Not register callback event: %{public}d", event);
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
            },
            [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set first param invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set second param invalid");
            });
    }
}

template<typename T>
void NapiAVSessionCallback::HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("Not register callback event: %{public}d", event);
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
            },
            [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set first param invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set second param invalid");
            });
    }
}

void NapiAVSessionCallback::OnPlay()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlay");
    HandleEvent(EVENT_PLAY);
}

void NapiAVSessionCallback::OnPause()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPause");
    HandleEvent(EVENT_PAUSE);
}

void NapiAVSessionCallback::OnStop()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnStop");
    HandleEvent(EVENT_STOP);
}

void NapiAVSessionCallback::OnPlayNext()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayNext");
    HandleEvent(EVENT_PLAY_NEXT);
}

void NapiAVSessionCallback::OnPlayPrevious()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayPrevious");
    HandleEvent(EVENT_PLAY_PREVIOUS);
}

void NapiAVSessionCallback::OnFastForward(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnFastForward");
    HandleEvent(EVENT_FAST_FORWARD, time);
}

void NapiAVSessionCallback::OnRewind(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnRewind");
    HandleEvent(EVENT_REWIND, time);
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSeek");
    HandleEvent(EVENT_SEEK, time);
}

void NapiAVSessionCallback::OnSetSpeed(double speed)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetSpeed");
    HandleEvent(EVENT_SET_SPEED, speed);
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetLoopMode");
    if (loopMode == AVPlaybackState::LOOP_MODE_UNDEFINED) {
        HandleEvent(EVENT_SET_LOOP_MODE);
    } else {
        HandleEvent(EVENT_SET_LOOP_MODE, loopMode);
    }
}

void NapiAVSessionCallback::OnSetTargetLoopMode(int32_t targetLoopMode)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetTargetLoopMode");
    if (targetLoopMode == AVPlaybackState::LOOP_MODE_UNDEFINED) {
        HandleEvent(EVENT_SET_TARGET_LOOP_MODE);
    } else {
        HandleEvent(EVENT_SET_TARGET_LOOP_MODE, targetLoopMode);
    }
}

void NapiAVSessionCallback::OnToggleFavorite(const std::string& assertId)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnToggleFavorite");
    HandleEvent(EVENT_TOGGLE_FAVORITE, assertId);
}

void NapiAVSessionCallback::OnCustomData(const AAFwk::WantParams& data)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCustomData");
    HandleEvent(EVENT_CUSTOM_DATA, data);
}

void NapiAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnMediaKeyEvent");
    HandleEvent(EVENT_MEDIA_KEY_EVENT, std::make_shared<MMI::KeyEvent>(keyEvent));
}

void NapiAVSessionCallback::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnOutputDeviceChange");
    SLOGI("OnOutputDeviceChange with connectionState %{public}d", connectionState);
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, connectionState, outputDeviceInfo);
}

void NapiAVSessionCallback::OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCommonCommand");
    HandleEvent(EVENT_SEND_COMMON_COMMAND, commonCommand, commandArgs);
}

void NapiAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSkipToQueueItem");
    HandleEvent(EVENT_SKIP_TO_QUEUE_ITEM, itemId);
}

void NapiAVSessionCallback::OnAVCallAnswer()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnAnswer");
    HandleEvent(EVENT_AVCALL_ANSWER);
}

void NapiAVSessionCallback::OnAVCallHangUp()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnHangUp");
    HandleEvent(EVENT_AVCALL_HANG_UP);
}

void NapiAVSessionCallback::OnAVCallToggleCallMute()
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnToggleCallMute");
    HandleEvent(EVENT_AVCALL_TOGGLE_CALL_MUTE);
}

void NapiAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayFromAssetId");
    HandleEvent(EVENT_PLAY_FROM_ASSETID, assetId);
}

void NapiAVSessionCallback::OnPlayWithAssetId(const std::string& assetId)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayWithAssetId");
    HandleEvent(EVENT_PLAY_WITH_ASSETID, assetId);
}

void NapiAVSessionCallback::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCastDisplayChange");
    HandleEvent(EVENT_DISPLAY_CHANGE, castDisplayInfo);
}

void NapiAVSessionCallback::OnCastDisplaySizeChange(const CastDisplayInfo& castDisplayInfo)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCastDisplaySizeChange");
    HandleEvent(EVENT_DISPLAY_CHANGE, castDisplayInfo);
}

napi_status NapiAVSessionCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    SLOGI("Add callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, NapiUtils::ARGC_ONE, &ref);
    if (status != napi_ok) {
        SLOGE("napi_create_reference failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<NapiAsyncCallback>(env);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return napi_generic_failure;
        }
    }
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiAVSessionCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    SLOGI("Remove callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    if (callback == nullptr) {
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
        }
        callbacks_[event].clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

bool NapiAVSessionCallback::IsCallbacksEmpty(int32_t event)
{
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, true, "has no event");
    return callbacks_[event].empty();
}
}
