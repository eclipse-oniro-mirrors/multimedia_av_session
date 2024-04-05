/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
        asyncCallback_->CallWithFlag(*ref, isValid_);
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
                SLOGI("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
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
                SLOGI("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
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
                SLOGI("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
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
void NapiAVControllerCallback::HandleEventWithOrder(int32_t event, int state, const T& param)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle for event: %{public}d with state: %{public}d", event, state);
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        lock_.unlock();
        asyncCallback_->CallWithOrder(*ref, isValid_, state,
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
                SLOGI("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            [param](napi_env env, int& argc, napi_value *argv) {
                argc = NapiUtils::ARGC_ONE;
                auto status = NapiUtils::SetValue(env, param, *argv);
                CHECK_RETURN_VOID(status == napi_ok, "ControllerCallback SetValue invalid");
            });
        lock_.lock();
    }
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

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnPlaybackStateChange");
    HandleEventWithOrder(EVENT_PLAYBACK_STATE_CHANGE, state.GetState(), state);
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    AVSESSION_TRACE_SYNC_START("NapiAVControllerCallback::OnMetaDataChange");
    SLOGI("do metadata change notify with title %{public}s", data.GetTitle().c_str());
    HandleEventWithOrder(EVENT_META_DATA_CHANGE, -1, data);
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    HandleEvent(EVENT_ACTIVE_STATE_CHANGE, isActive);
}

void NapiAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    std::vector<std::string> stringCmds = NapiControlCommand::ConvertCommands(cmds);
    HandleEventWithOrder(EVENT_VALID_COMMAND_CHANGE, static_cast<int>(cmds.size()), stringCmds);
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

napi_status NapiAVControllerCallback::AddCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
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
    SLOGI("add callback with ref %{public}d, %{public}p, %{public}p", event, &ref, *(&ref));
    callbacks_[event].push_back(ref);
    return napi_ok;
}

napi_status NapiAVControllerCallback::RemoveCallback(napi_env env, int32_t event, napi_value callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("remove callback for event %{public}d", event);
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
    SLOGI("remove single callback with ref %{public}d, %{public}p, %{public}p", event, &ref, *(&ref));
    callbacks_[event].remove(ref);
    return napi_delete_reference(env, ref);
}

void NapiAVControllerCallback::AddCallbackForSessionDestroy(const std::function<void(void)>& sessionDestroyCallback)
{
    SLOGE("add callback for session destroy notify");
    sessionDestroyCallback_ = sessionDestroyCallback;
}
}
