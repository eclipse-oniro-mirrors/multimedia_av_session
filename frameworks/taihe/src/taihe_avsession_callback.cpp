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
#define LOG_TAG "TaiheAVSessionCallback"
#endif

#include "taihe_avsession_callback.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
TaiheAVSessionCallback::TaiheAVSessionCallback(ani_env* env)
{
    SLOGI("construct TaiheAVSessionCallback");
    isValid_ = std::make_shared<bool>(true);
    if (env != nullptr) {
        env_ = env;
    }
}

TaiheAVSessionCallback::~TaiheAVSessionCallback()
{
    SLOGI("destroy TaiheAVSessionCallback");
    if (isValid_) {
        *isValid_ = false;
    }
}

void TaiheAVSessionCallback::HandleEvent(int32_t event, TaiheFuncExecute execute)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle event for %{public}d", event);
    CHECK_RETURN_VOID(asyncCallback_ != nullptr, "asyncCallback_ is nullptr");

    for (auto callbackEntry = callbacks_[event].begin(); callbackEntry != callbacks_[event].end(); ++callbackEntry) {
        asyncCallback_->CallWithFunc(*callbackEntry, isValid_,
            [this, callbackEntry, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (callbackEntry == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            execute);
    }
}

void TaiheAVSessionCallback::OnPlay()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPlay");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_PLAY, execute);
}

void TaiheAVSessionCallback::OnPause()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPause");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_PAUSE, execute);
}

void TaiheAVSessionCallback::OnStop()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnStop");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_STOP, execute);
}

void TaiheAVSessionCallback::OnPlayNext()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPlayNext");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_PLAY_NEXT, execute);
}

void TaiheAVSessionCallback::OnPlayPrevious()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPlayPrevious");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_PLAY_PREVIOUS, execute);
}

void TaiheAVSessionCallback::OnFastForward(int64_t time)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnFastForward");
    auto execute = [time](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int64_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int64_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(time);
    };
    HandleEvent(EVENT_FAST_FORWARD, execute);
}

void TaiheAVSessionCallback::OnRewind(int64_t time)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnRewind");
    auto execute = [time](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int64_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int64_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(time);
    };
    HandleEvent(EVENT_REWIND, execute);
}

void TaiheAVSessionCallback::OnSeek(int64_t time)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnSeek");
    auto execute = [time](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int64_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int64_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(time);
    };
    HandleEvent(EVENT_SEEK, execute);
}

void TaiheAVSessionCallback::OnSetSpeed(double speed)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnSetSpeed");
    auto execute = [speed](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(double)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(double)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(speed);
    };
    HandleEvent(EVENT_SET_SPEED, execute);
}

void TaiheAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnSetLoopMode");
    LoopMode loopModeTaihe = LoopMode::from_value(loopMode);
    auto execute = [loopModeTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(LoopMode)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(LoopMode)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(loopModeTaihe);
    };
    HandleEvent(EVENT_SET_LOOP_MODE, execute);
}

void TaiheAVSessionCallback::OnSetTargetLoopMode(int32_t targetLoopMode)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnSetTargetLoopMode");
    auto execute = [targetLoopMode](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(targetLoopMode);
    };
    HandleEvent(EVENT_SET_TARGET_LOOP_MODE, execute);
}

void TaiheAVSessionCallback::OnToggleFavorite(const std::string &assertId)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnToggleFavorite");
    dataContext_.assetId = assertId;
    string_view assertIdTaihe = dataContext_.assetId;
    auto execute = [assertIdTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(string_view)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(assertIdTaihe);
    };
    HandleEvent(EVENT_TOGGLE_FAVORITE, execute);
}

void TaiheAVSessionCallback::OnMediaKeyEvent(const OHOS::MMI::KeyEvent &keyEvent)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnMediaKeyEvent");
    auto execute = [keyEvent](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto keyEventAni = TaiheUtils::ToAniKeyEvent(keyEvent);
        CHECK_RETURN_VOID(keyEventAni != nullptr, "convert keyEvent to ani object failed");
        uintptr_t keyEventTaihe = reinterpret_cast<uintptr_t>(keyEventAni);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(keyEventTaihe);
    };
    HandleEvent(EVENT_MEDIA_KEY_EVENT, execute);
}

void TaiheAVSessionCallback::OnOutputDeviceChange(const int32_t connectionState,
    const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfo)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnOutputDeviceChange");
    SLOGI("OnOutputDeviceChange with connectionState %{public}d", connectionState);
    ConnectionState stateTaihe = ConnectionState::from_value(connectionState);
    OutputDeviceInfo infoTaihe = TaiheUtils::ToTaiheOutputDeviceInfo(outputDeviceInfo);
    auto execute = [stateTaihe, infoTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(ConnectionState, OutputDeviceInfo const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(ConnectionState, OutputDeviceInfo const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe, infoTaihe);
    };
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, execute);
}

void TaiheAVSessionCallback::OnCommonCommand(const std::string &commonCommand,
    const OHOS::AAFwk::WantParams &commandArgs)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnCommonCommand");
    dataContext_.commonCommand = string(commonCommand);
    string_view commonCommandTaihe = dataContext_.commonCommand;
    auto execute = [commonCommandTaihe, commandArgs](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto commandArgsAni = TaiheUtils::ToAniWantParams(commandArgs);
        CHECK_RETURN_VOID(commandArgsAni != nullptr, "convert WantParams to ani object failed");
        uintptr_t commandArgsTaihe = reinterpret_cast<uintptr_t>(commandArgsAni);
        std::shared_ptr<taihe::callback<void(string_view, uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view, uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(commonCommandTaihe, commandArgsTaihe);
    };
    HandleEvent(EVENT_SEND_COMMON_COMMAND, execute);
}

void TaiheAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnSkipToQueueItem");
    auto execute = [itemId](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(itemId);
    };
    HandleEvent(EVENT_SKIP_TO_QUEUE_ITEM, execute);
}

void TaiheAVSessionCallback::OnAVCallAnswer()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnAnswer");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_AVCALL_ANSWER, execute);
}

void TaiheAVSessionCallback::OnAVCallHangUp()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnHangUp");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_AVCALL_HANG_UP, execute);
}

void TaiheAVSessionCallback::OnAVCallToggleCallMute()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnToggleCallMute");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_AVCALL_TOGGLE_CALL_MUTE, execute);
}

void TaiheAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPlayFromAssetId");
    auto execute = [assetId](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int64_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int64_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(assetId);
    };
    HandleEvent(EVENT_PLAY_FROM_ASSETID, execute);
}

void TaiheAVSessionCallback::OnPlayWithAssetId(const std::string &assetId)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnPlayWithAssetId");
    dataContext_.playAssetId = string(assetId);
    string_view assetIdTaihe = dataContext_.playAssetId;
    auto execute = [assetIdTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(string_view)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(assetIdTaihe);
    };
    HandleEvent(EVENT_PLAY_WITH_ASSETID, execute);
}

void TaiheAVSessionCallback::OnCastDisplayChange(const OHOS::AVSession::CastDisplayInfo &castDisplayInfo)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnCastDisplayChange");
    CastDisplayInfo castDisplayInfoTaihe = TaiheUtils::ToTaiheCastDisplayInfo(castDisplayInfo);
    auto execute = [castDisplayInfoTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(CastDisplayInfo const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(CastDisplayInfo const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(castDisplayInfoTaihe);
    };
    HandleEvent(EVENT_DISPLAY_CHANGE, execute);
}

void TaiheAVSessionCallback::OnCustomData(const OHOS::AAFwk::WantParams &customData)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionCallback::OnCustomData");
    auto execute = [this, customData](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto customDataAni = TaiheUtils::ToAniWantParams(customData);
        CHECK_RETURN_VOID(customDataAni != nullptr, "convert WantParams to ani object failed");
        uintptr_t customDataTaihe = reinterpret_cast<uintptr_t>(customDataAni);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(customDataTaihe);
    };
    HandleEvent(EVENT_CUSTOM_DATA_CHANGE, execute);
}

int32_t TaiheAVSessionCallback::AddCallback(int32_t event, std::shared_ptr<uintptr_t> callback)
{
    SLOGI("Add callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb == nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been registered");
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);

    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<TaiheAsyncCallback>(env_, mainHandler_);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return OHOS::AVSession::ERR_NO_MEMORY;
        }
    }
    SLOGI("add callback with callback %{public}d", event);
    callbacks_[event].push_back(callback);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionCallback::RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> callback)
{
    SLOGI("Remove callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callback == nullptr) {
        SLOGD("remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb != nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been remove");
    callbacks_[event].remove(targetCb);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

bool TaiheAVSessionCallback::IsCallbacksEmpty(int32_t event)
{
    return callbacks_[event].empty();
}
} // namespace ANI::AVSession