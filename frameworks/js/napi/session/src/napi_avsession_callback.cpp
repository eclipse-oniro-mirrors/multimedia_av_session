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

void NapiAVSessionCallback::HandleEvent(int32_t event, std::string callBackName)
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
            }, callBackName);
    }
}

template<typename T>
void NapiAVSessionCallback::HandleEvent(int32_t event, std::string callBackName, const T& param)
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
            }, callBackName,
            [param](napi_env env, int& argc, napi_value* argv) {
                argc = NapiUtils::ARGC_ONE;
                NapiUtils::SetValue(env, param, *argv);
            });
    }
}

template<typename T>
void NapiAVSessionCallback::HandleEvent(int32_t event, std::string callBackName,
    const std::string& firstParam, const T& secondParam)
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
            }, callBackName,
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
void NapiAVSessionCallback::HandleEvent(int32_t event,
    std::string callBackName, const int32_t firstParam, const T& secondParam)
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
            }, callBackName,
            [firstParam, secondParam](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set first param invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "AVSessionCallback set second param invalid");
            });
    }
}

void NapiAVSessionCallback::OnPlay(const AVControlCommand& cmd)
{
    std::string callBackName = "NapiAVSessionCallback::OnPlay";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlay");
    CommandInfo cmdInfo;
    cmd.GetCommandInfo(cmdInfo);
    HandleEvent(EVENT_PLAY, callBackName, std::make_shared<CommandInfo>(cmdInfo));
}

void NapiAVSessionCallback::OnPause()
{
    std::string callBackName = "NapiAVSessionCallback::OnPause";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPause");
    HandleEvent(EVENT_PAUSE, callBackName);
}

void NapiAVSessionCallback::OnStop()
{
    std::string callBackName = "NapiAVSessionCallback::OnStop";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnStop");
    HandleEvent(EVENT_STOP, callBackName);
}

void NapiAVSessionCallback::OnPlayNext(const AVControlCommand& cmd)
{
    std::string callBackName = "NapiAVSessionCallback::OnPlayNext";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayNext");
    CommandInfo cmdInfo;
    cmd.GetCommandInfo(cmdInfo);
    HandleEvent(EVENT_PLAY_NEXT, callBackName, std::make_shared<CommandInfo>(cmdInfo));
}

void NapiAVSessionCallback::OnPlayPrevious(const AVControlCommand& cmd)
{
    std::string callBackName = "NapiAVSessionCallback::OnPlayPrevious";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayPrevious");
    CommandInfo cmdInfo;
    cmd.GetCommandInfo(cmdInfo);
    HandleEvent(EVENT_PLAY_PREVIOUS, callBackName, std::make_shared<CommandInfo>(cmdInfo));
}

void NapiAVSessionCallback::OnFastForward(int64_t time, const AVControlCommand& cmd)
{
    std::string callBackName = "NapiAVSessionCallback::OnFastForward";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnFastForward");
    CommandInfo cmdInfo;
    cmd.GetCommandInfo(cmdInfo);
    HandleEvent(EVENT_FAST_FORWARD, callBackName, time, std::make_shared<CommandInfo>(cmdInfo));
}

void NapiAVSessionCallback::OnRewind(int64_t time, const AVControlCommand& cmd)
{
    std::string callBackName = "NapiAVSessionCallback::OnRewind";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnRewind");
    CommandInfo cmdInfo;
    cmd.GetCommandInfo(cmdInfo);
    HandleEvent(EVENT_REWIND, callBackName, time, std::make_shared<CommandInfo>(cmdInfo));
}

void NapiAVSessionCallback::OnSeek(int64_t time)
{
    std::string callBackName = "NapiAVSessionCallback::OnSeek";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSeek");
    HandleEvent(EVENT_SEEK, callBackName, time);
}

void NapiAVSessionCallback::OnSetSpeed(double speed)
{
    std::string callBackName = "NapiAVSessionCallback::OnSetSpeed";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetSpeed");
    HandleEvent(EVENT_SET_SPEED, callBackName, speed);
}

void NapiAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    std::string callBackName = "NapiAVSessionCallback::OnSetLoopMode";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetLoopMode");
    if (loopMode == AVPlaybackState::LOOP_MODE_UNDEFINED) {
        HandleEvent(EVENT_SET_LOOP_MODE, callBackName);
    } else {
        HandleEvent(EVENT_SET_LOOP_MODE, callBackName, loopMode);
    }
}

void NapiAVSessionCallback::OnSetTargetLoopMode(int32_t targetLoopMode)
{
    std::string callBackName = "NapiAVSessionCallback::OnSetTargetLoopMode";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSetTargetLoopMode");
    if (targetLoopMode == AVPlaybackState::LOOP_MODE_UNDEFINED) {
        HandleEvent(EVENT_SET_TARGET_LOOP_MODE, callBackName);
    } else {
        HandleEvent(EVENT_SET_TARGET_LOOP_MODE, callBackName, targetLoopMode);
    }
}

void NapiAVSessionCallback::OnToggleFavorite(const std::string& assertId)
{
    std::string callBackName = "NapiAVSessionCallback::OnToggleFavorite";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnToggleFavorite");
    HandleEvent(EVENT_TOGGLE_FAVORITE, callBackName, assertId);
}

void NapiAVSessionCallback::OnCustomData(const AAFwk::WantParams& data)
{
    std::string callBackName = "NapiAVSessionCallback::OnCustomData";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCustomData");
    HandleEvent(EVENT_CUSTOM_DATA, callBackName, data);
}

void NapiAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    std::string callBackName = "NapiAVSessionCallback::OnMediaKeyEvent";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnMediaKeyEvent");
    HandleEvent(EVENT_MEDIA_KEY_EVENT, callBackName, std::make_shared<MMI::KeyEvent>(keyEvent));
}

void NapiAVSessionCallback::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    std::string callBackName = "NapiAVSessionCallback::OnOutputDeviceChange";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnOutputDeviceChange");
    SLOGI("OnOutputDeviceChange with connectionState %{public}d", connectionState);
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, callBackName, connectionState, outputDeviceInfo);
}

void NapiAVSessionCallback::OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    std::string callBackName = "NapiAVSessionCallback::OnCommonCommand";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCommonCommand");
    HandleEvent(EVENT_SEND_COMMON_COMMAND, callBackName, commonCommand, commandArgs);
}

void NapiAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    std::string callBackName = "NapiAVSessionCallback::OnSkipToQueueItem";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnSkipToQueueItem");
    HandleEvent(EVENT_SKIP_TO_QUEUE_ITEM, callBackName, itemId);
}

void NapiAVSessionCallback::OnAVCallAnswer()
{
    std::string callBackName = "NapiAVSessionCallback::OnAVCallAnswer";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnAnswer");
    HandleEvent(EVENT_AVCALL_ANSWER, callBackName);
}

void NapiAVSessionCallback::OnAVCallHangUp()
{
    std::string callBackName = "NapiAVSessionCallback::OnAVCallHangUp";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnHangUp");
    HandleEvent(EVENT_AVCALL_HANG_UP, callBackName);
}

void NapiAVSessionCallback::OnAVCallToggleCallMute()
{
    std::string callBackName = "NapiAVSessionCallback::OnAVCallToggleCallMute";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnToggleCallMute");
    HandleEvent(EVENT_AVCALL_TOGGLE_CALL_MUTE, callBackName);
}

void NapiAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    std::string callBackName = "NapiAVSessionCallback::OnPlayFromAssetId";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayFromAssetId");
    HandleEvent(EVENT_PLAY_FROM_ASSETID, callBackName, assetId);
}

void NapiAVSessionCallback::OnPlayWithAssetId(const std::string& assetId)
{
    std::string callBackName = "NapiAVSessionCallback::OnPlayWithAssetId";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnPlayWithAssetId");
    HandleEvent(EVENT_PLAY_WITH_ASSETID, callBackName, assetId);
}

void NapiAVSessionCallback::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    std::string callBackName = "NapiAVSessionCallback::OnCastDisplayChange";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnCastDisplayChange");
    HandleEvent(EVENT_DISPLAY_CHANGE, callBackName, castDisplayInfo);
}

void NapiAVSessionCallback::OnDesktopLyricVisibilityChanged(bool isVisible)
{
    std::string callBackName = "NapiAVSessionCallback::OnDesktopLyricVisibilityChanged";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnDesktopLyricVisibilityChanged");
    HandleEvent(EVENT_DESKTOP_LYRIC_VISIBILITY_CHANGED, callBackName, isVisible);
}

void NapiAVSessionCallback::OnDesktopLyricStateChanged(const DesktopLyricState &state)
{
    std::string callBackName = "NapiAVSessionCallback::OnDesktopLyricStateChanged";
    AVSESSION_TRACE_SYNC_START("NapiAVSessionCallback::OnDesktopLyricStateChanged");
    HandleEvent(EVENT_DESKTOP_LYRIC_STATE_CHANGED, callBackName, state);
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
