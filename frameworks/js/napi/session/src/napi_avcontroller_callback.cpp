/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "napi_avcontroller_callback.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "avsession_utils.h"
#include "napi_control_command.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "napi_utils.h"

namespace OHOS::AVSession {
NapiAVControllerCallback::NapiAVControllerCallback()
{
    SLOGI("Construct NapiAVControllerCallback");
    isValid_ = std::make_shared<bool>(true);
}

NapiAVControllerCallback::~NapiAVControllerCallback()
{
    SLOGI("Destroy NapiAVControllerCallback");
    *isValid_ = false;
}

void NapiAVControllerCallback::HandleEvent(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle event for %{public}d", event);
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
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
void NapiAVControllerCallback::HandleEvent(int32_t event, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle for event: %{public}d with size: %{public}d", event, static_cast<int>(callbacks_[event].size()));
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            [param](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_ONE;
                auto status = NapiUtils::SetValue(env, param, *argv);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

template<typename T>
void NapiAVControllerCallback::HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle event for %{public}d", event);
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            [firstParam, secondParam](napi_env env, int& argc,
                napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

template<typename T>
void NapiAVControllerCallback::HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle event for %{public}d", event);
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_,
            [this, ref, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            [firstParam, secondParam](napi_env env, int& argc,
                napi_value *argv) {
                argc = NapiUtils::ARGC_TWO;
                auto status = NapiUtils::SetValue(env, firstParam, argv[0]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
                status = NapiUtils::SetValue(env, secondParam, argv[1]);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

template<typename T>
void NapiAVControllerCallback::HandleEventWithThreadSafe(int32_t event, int state, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("event:%{public}d|num:%{public}d|state:%{public}d",
        event, static_cast<int>(callbacks_[event].size()), state);
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        CallWithThreadSafe(*ref, isValid_, state, threadSafeFunction_,
            [this, ref, event]() {
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (ref == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            [param](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_ONE;
                auto status = NapiUtils::SetValue(env, param, *argv);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
    }
}

void NapiAVControllerCallback::CallWithThreadSafe(napi_ref& method, std::shared_ptr<bool> isValid, int state,
    napi_threadsafe_function threadSafeFunction, const std::function<bool()>& checkCallbackValid, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");
    SLOGD("do CallWithThreadSafe with state %{public}d", state);
    DataContextForThreadSafe* data =
        new DataContextForThreadSafe { method, state, isValid, std::move(getter), checkCallbackValid };
    if (threadSafeFunction != nullptr) {
        SLOGD("do CallWithThreadSafe check threadSafeFunction alive and cache data");
        napi_call_threadsafe_function(threadSafeFunction, data, napi_tsfn_nonblocking);
    } else {
        SLOGE("do CallWithThreadSafe check threadSafeFunction with null");
        delete data;
        data = nullptr;
    }
    SLOGD("do CallWithThreadSafe with state %{public}d done", state);
}

void NapiAVControllerCallback::ThreadSafeCallback(napi_env env, napi_value js_cb, void* context, void* data)
{
    SLOGD("do ThreadSafeCallback in");
    AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::ThreadSafeCallback");
    std::shared_ptr<DataContextForThreadSafe> appData(static_cast<DataContextForThreadSafe*>(data),
        [](DataContextForThreadSafe* ptr) {
        delete ptr;
        ptr = nullptr;
    });

    int argc = 0;
    napi_value argv[ARGC_MAX] = { nullptr };
    if (appData->getter) {
        argc = ARGC_MAX;
        appData->getter(env, argc, argv);
    }

    SLOGD("queue uv_after_work_cb with state %{public}d", static_cast<int>(appData->state));
    if (!*appData->isValid) {
        SLOGE("ThreadSafeCallback failed for appData is invalid.");
        return;
    }
    napi_value global {};
    napi_get_global(env, &global);
    napi_value function {};
    if (!appData->checkCallbackValid()) {
        SLOGE("Get func reference failed for func has been deleted.");
        return;
    }
    napi_get_reference_value(env, appData->method, &function);
    napi_value result;
    if (!appData->checkCallbackValid()) {
        SLOGE("Call func failed for func has been deleted.");
        return;
    }
    napi_status status = napi_call_function(env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
    SLOGD("do ThreadSafeCallback done with state %{public}d", static_cast<int>(appData->state));
}

void NapiAVControllerCallback::OnAVCallStateChange(const AVCallState& avCallState)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnAVCallStateChange");
    HandleEvent(EVENT_AVCALL_STATE_CHANGE, avCallState);
}

void NapiAVControllerCallback::OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnAVCallMetaDataChange");
    HandleEvent(EVENT_AVCALL_META_DATA_CHANGE, avCallMetaData);
}

void NapiAVControllerCallback::OnSessionDestroy()
{
    HandleEvent(EVENT_SESSION_DESTROY);
    SLOGD("callback for sessionDestroy, check callback");
    if (sessionDestroyCallback_ != nullptr) {
        SLOGI("notify session Destroy for repeat");
        sessionDestroyCallback_();
        sessionDestroyCallback_ = nullptr;
        SLOGD("notify session Destroy for repeat done");
    }
}

void NapiAVControllerCallback::OnCustomData(const AAFwk::WantParams& data)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnCustomData");
    HandleEvent(EVENT_CUSTOM_DATA, data);
}

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnPlaybackStateChange");
    SLOGD("OnPlaybackStateChange %{public}d", state.GetState());
    HandleEventWithThreadSafe(EVENT_PLAYBACK_STATE_CHANGE,
        state.GetMask().test(AVPlaybackState::PLAYBACK_KEY_STATE) ? state.GetState() : -1, state);
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnMetaDataChange");
    SLOGI("do metadata change notify with title %{public}s",
        AVSessionUtils::GetAnonyTitle(data.GetTitle().c_str()).c_str());
    HandleEventWithThreadSafe(EVENT_META_DATA_CHANGE, -1, data);
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    HandleEvent(EVENT_ACTIVE_STATE_CHANGE, isActive);
}

void NapiAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGI("do OnValidCommandChange in NapiCallback with size %{public}d", static_cast<int>(cmds.size()));
    std::vector<std::string> stringCmds = NapiControlCommand::ConvertCommands(cmds);
    HandleEventWithThreadSafe(EVENT_VALID_COMMAND_CHANGE, static_cast<int>(cmds.size()), stringCmds);
}

void NapiAVControllerCallback::OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& info)
{
    HandleEvent(EVENT_OUTPUT_DEVICE_CHANGE, connectionState, info);
}

void NapiAVControllerCallback::OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnSessionEventChange");
    HandleEvent(EVENT_SESSION_EVENT_CHANGE, event, args);
}

void NapiAVControllerCallback::OnQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnQueueItemsChange");
    HandleEvent(EVENT_QUEUE_ITEMS_CHANGE, items);
}

void NapiAVControllerCallback::OnQueueTitleChange(const std::string& title)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnQueueTitleChange");
    HandleEvent(EVENT_QUEUE_TITLE_CHANGE, title);
}

void NapiAVControllerCallback::OnExtrasChange(const AAFwk::WantParams& extras)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnExtrasChange");
    HandleEvent(EVENT_EXTRAS_CHANGE, extras);
}

void NapiAVControllerCallback::OnDesktopLyricVisibilityChanged(bool isVisible)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnDesktopLyricVisibilityChanged");
    HandleEvent(EVENT_DESKTOP_LYRIC_VISIBILITY_CHANGED, isVisible);
}

void NapiAVControllerCallback::OnDesktopLyricStateChanged(const DesktopLyricState& state)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnDesktopLyricStateChanged");
    HandleEvent(EVENT_DESKTOP_LYRIC_STATE_CHANGED, state);
}

napi_status NapiAVControllerCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    napi_ref ref = nullptr;

    if (threadSafeFunction_ == nullptr) {
        SLOGI("addcallback with thread safe init");
        napi_value resourceName = nullptr;
        napi_create_string_utf8(env, "ThreadSafeFunction in NapiAVControllerCallback", NAPI_AUTO_LENGTH, &resourceName);
        napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1, nullptr, nullptr,
            nullptr, ThreadSafeCallback, &threadSafeFunction_);
    }
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
    SLOGI("add callback with ref %{public}d", event);
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiAVControllerCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("remove callback for event %{public}d", event);
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX, napi_generic_failure, "has no event");
    if (callback == nullptr) {
        SLOGD("Remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(ret == napi_ok, ret, "delete callback reference failed");
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, callbacks_[event], callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    SLOGI("remove single callback with ref %{public}d", event);
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

void NapiAVControllerCallback::AddCallbackForSessionDestroy(const std::function<void(void)>& sessionDestroyCallback)
{
    SLOGE("add callback for session destroy notify");
    sessionDestroyCallback_ = sessionDestroyCallback;
}
}
