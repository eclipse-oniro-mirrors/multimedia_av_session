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
#define LOG_TAG "TaiheAVControllerCallback"
#endif

#include "taihe_avcontroller_callback.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_control_command.h"
#include "taihe_utils.h"
#include "avsession_utils.h"

namespace ANI::AVSession {
std::mutex TaiheAVControllerCallback::sWorkerMutex_;
TaiheAVControllerCallback::TaiheAVControllerCallback(ani_env* env)
{
    SLOGI("Construct TaiheAVControllerCallback");
    isValid_ = std::make_shared<bool>(true);
    if (env != nullptr) {
        env_ = env;
    }
}

TaiheAVControllerCallback::~TaiheAVControllerCallback()
{
    SLOGI("Destroy TaiheAVControllerCallback");
    if (isValid_) {
        *isValid_ = false;
    }
}

void TaiheAVControllerCallback::HandleEvent(int32_t event, TaiheFuncExecute execute)
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

void TaiheAVControllerCallback::HandleEventWithThreadSafe(int32_t event, int32_t state, TaiheFuncExecute execute)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("event:%{public}d|num:%{public}d|state:%{public}d",
        event, static_cast<int32_t>(callbacks_[event].size()), state);
    for (auto callback = callbacks_[event].begin(); callback != callbacks_[event].end(); ++callback) {
        CallWithThreadSafe(*callback, isValid_, state,
            [this, callback, event]() {
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (callback == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            execute);
    }
}

void TaiheAVControllerCallback::CallWithThreadSafe(std::shared_ptr<uintptr_t> method, std::shared_ptr<bool> isValid,
    int state, const std::function<bool()>& checkCallbackValid, TaiheFuncExecute execute)
{
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");
    CHECK_RETURN_VOID(mainHandler_ != nullptr, "mainHandler_ is nullptr");
    SLOGD("do CallWithThreadSafe with state %{public}d", state);
    DataContextForThreadSafe* data =
        new DataContextForThreadSafe { method, state, isValid, std::move(execute), checkCallbackValid };
    auto sharePtr = shared_from_this();
    auto task = [data, sharePtr, this]() {
        if (sharePtr != nullptr) {
            sharePtr->ThreadSafeCallback(this->env_, data);
        }
    };
    mainHandler_->PostTask(task, "CallWithThreadSafe", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TaiheAVControllerCallback::ThreadSafeCallback(ani_env *env, DataContextForThreadSafe *data)
{
    SLOGD("do ThreadSafeCallback in");
    std::lock_guard<std::mutex> lock(sWorkerMutex_);
    CHECK_AND_RETURN_LOG((data != nullptr) && (data->method != nullptr),
        "ThreadSafeCallbackWork: no memory");
    std::shared_ptr<DataContextForThreadSafe> appData(static_cast<DataContextForThreadSafe*>(data),
        [](DataContextForThreadSafe* ptr) {
        delete ptr;
        ptr = nullptr;
    });
    CHECK_RETURN_VOID(appData != nullptr, "ThreadSafeCallback: appData is nullptr");
    CHECK_RETURN_VOID(appData->isValid != nullptr, "ThreadSafeCallback: isValid is nullptr");
    SLOGD("work_cb with state %{public}d", static_cast<int>(appData->state));
    if (!*appData->isValid) {
        SLOGE("ThreadSafeCallback failed for appData is invalid.");
        return;
    }
    if (!appData->checkCallbackValid()) {
        SLOGE("Call func failed for func has been deleted.");
        return;
    }
    do {
        SLOGI("Call func execute");
        if (appData->execute) {
            appData->execute(appData->method);
        }
    } while (0);
    SLOGD("do ThreadSafeCallback done with state %{public}d", static_cast<int>(appData->state));
}

void TaiheAVControllerCallback::OnAVCallStateChange(const OHOS::AVSession::AVCallState &avCallState)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnAVCallStateChange");
    AVCallState stateTaihe = TaiheUtils::ToTaiheAVCallState(avCallState);
    auto execute = [this, stateTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(AVCallState const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVCallState const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe);
    };
    HandleEvent(EVENT_AVCALL_STATE_CHANGE, execute);
}

void TaiheAVControllerCallback::OnAVCallMetaDataChange(const OHOS::AVSession::AVCallMetaData &avCallMetaData)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnAVCallMetaDataChange");
    auto execute = [this, avCallMetaData](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        CallMetadata dataTaihe = TaiheUtils::ToTaiheAVCallMetaData(avCallMetaData);
        std::shared_ptr<taihe::callback<void(CallMetadata const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(CallMetadata const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(dataTaihe);
    };
    HandleEvent(EVENT_AVCALL_META_DATA_CHANGE, execute);
}

void TaiheAVControllerCallback::OnSessionDestroy()
{
    auto execute = [this](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_SESSION_DESTROY, execute);
    SLOGD("callback for sessionDestroy, check callback");
    if (sessionDestroyCallback_ != nullptr) {
        SLOGI("notify session Destroy for repeat");
        sessionDestroyCallback_();
        sessionDestroyCallback_ = nullptr;
        SLOGD("notify session Destroy for repeat done");
    }
}

void TaiheAVControllerCallback::OnPlaybackStateChange(const OHOS::AVSession::AVPlaybackState &state)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnPlaybackStateChange");
    SLOGD("OnPlaybackStateChange %{public}d", state.GetState());
    auto execute = [this, state](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVPlaybackState stateTaihe = TaiheUtils::ToTaiheAVPlaybackState(state);
        std::shared_ptr<taihe::callback<void(AVPlaybackState const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVPlaybackState const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe);
    };
    HandleEventWithThreadSafe(EVENT_PLAYBACK_STATE_CHANGE, state.GetState(), execute);
}

void TaiheAVControllerCallback::OnMetaDataChange(const OHOS::AVSession::AVMetaData &data)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnMetaDataChange");
    SLOGI("do metadata change notify with title %{public}s",
        OHOS::AVSession::AVSessionUtils::GetAnonyTitle(data.GetTitle()).c_str());
    auto execute = [this, data](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVMetadata dataTaihe = TaiheUtils::ToTaiheAVMetaData(data);
        std::shared_ptr<taihe::callback<void(AVMetadata const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVMetadata const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(dataTaihe);
    };
    HandleEventWithThreadSafe(EVENT_META_DATA_CHANGE, -1, execute);
}

void TaiheAVControllerCallback::OnActiveStateChange(bool isActive)
{
    auto execute = [this, isActive](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(bool)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(bool)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(isActive);
    };
    HandleEvent(EVENT_ACTIVE_STATE_CHANGE, execute);
}

void TaiheAVControllerCallback::OnValidCommandChange(const std::vector<int32_t> &cmds)
{
    SLOGI("do OnValidCommandChange in TaiheCallback with size %{public}d", static_cast<int32_t>(cmds.size()));
    std::vector<std::string> stringCmds = TaiheControlCommand::ConvertCommands(cmds);
    dataContext_.cmds = TaiheUtils::ToTaiheStringArray(stringCmds);
    array_view<string> cmdsTaihe = dataContext_.cmds;
    auto execute = [this, cmdsTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(array_view<string>)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(array_view<string>)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(cmdsTaihe);
    };
    HandleEventWithThreadSafe(EVENT_VALID_COMMAND_CHANGE, static_cast<int32_t>(cmdsTaihe.size()), execute);
}

void TaiheAVControllerCallback::OnOutputDeviceChange(const int32_t connectionState,
    const OHOS::AVSession::OutputDeviceInfo &info)
{
    ConnectionState stateTaihe = ConnectionState::from_value(connectionState);
    OutputDeviceInfo infoTaihe = TaiheUtils::ToTaiheOutputDeviceInfo(info);
    auto execute = [this, stateTaihe, infoTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(ConnectionState, OutputDeviceInfo const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(ConnectionState, OutputDeviceInfo const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe, infoTaihe);
    };
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, execute);
}

void TaiheAVControllerCallback::OnSessionEventChange(const std::string &event, const OHOS::AAFwk::WantParams &args)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnSessionEventChange");
    dataContext_.sessionEvent = string(event);
    string_view eventTaihe = dataContext_.sessionEvent;
    auto execute = [this, eventTaihe, args](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto argsAni = TaiheUtils::ToAniWantParams(args);
        CHECK_RETURN_VOID(argsAni != nullptr, "convert WantParams to ani object failed");
        uintptr_t argsTaihe = reinterpret_cast<uintptr_t>(argsAni);
        std::shared_ptr<taihe::callback<void(string_view, uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view, uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(eventTaihe, argsTaihe);
    };
    HandleEvent(EVENT_SESSION_EVENT_CHANGE, execute);
}

void TaiheAVControllerCallback::OnQueueItemsChange(const std::vector<OHOS::AVSession::AVQueueItem> &items)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnQueueItemsChange");
    auto execute = [this, items](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        array<AVQueueItem> queueItems = TaiheUtils::ToTaiheAVQueueItemArray(items);
        array_view<AVQueueItem> queueItemTaihe = queueItems;
        std::shared_ptr<taihe::callback<void(array_view<AVQueueItem>)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(array_view<AVQueueItem>)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(queueItemTaihe);
    };
    HandleEvent(EVENT_QUEUE_ITEMS_CHANGE, execute);
}

void TaiheAVControllerCallback::OnQueueTitleChange(const std::string &title)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnQueueTitleChange");
    dataContext_.queueTitle = string(title);
    string_view titleTaihe = dataContext_.queueTitle;
    auto execute = [this, titleTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(string_view)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(titleTaihe);
    };
    HandleEvent(EVENT_QUEUE_TITLE_CHANGE, execute);
}

void TaiheAVControllerCallback::OnExtrasChange(const OHOS::AAFwk::WantParams &extras)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnExtrasChange");
    auto execute = [this, extras](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto extrasAni = TaiheUtils::ToAniWantParams(extras);
        CHECK_RETURN_VOID(extrasAni != nullptr, "convert WantParams to ani object failed");
        uintptr_t extrasTaihe = reinterpret_cast<uintptr_t>(extrasAni);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(extrasTaihe);
    };
    HandleEvent(EVENT_EXTRAS_CHANGE, execute);
}

void TaiheAVControllerCallback::OnCustomData(const OHOS::AAFwk::WantParams &customData)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVControllerCallback::OnCustomData");
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

int32_t TaiheAVControllerCallback::AddCallback(int32_t event, std::shared_ptr<uintptr_t> callback)
{
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

int32_t TaiheAVControllerCallback::RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("remove callback for event %{public}d", event);
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

void TaiheAVControllerCallback::AddCallbackForSessionDestroy(const std::function<void(void)> &sessionDestroyCallback)
{
    SLOGE("add callback for session destroy notify");
    sessionDestroyCallback_ = sessionDestroyCallback;
}
} // namespace ANI::AVSession