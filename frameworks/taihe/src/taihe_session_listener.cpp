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
#define LOG_TAG "TaiheSessionListener"
#endif

#include <memory>

#include "taihe_session_listener.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "avsession_trace.h"
#include "avsession_errors.h"
#include "avsession_controller.h"
#include "avsession_controller_proxy.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
TaiheSessionListener::TaiheSessionListener()
{
    SLOGI("construct");
    isValid_ = std::make_shared<bool>(true);
}

TaiheSessionListener::~TaiheSessionListener()
{
    SLOGI("destroy");
    if (isValid_) {
        *isValid_ = false;
    }
}

void TaiheSessionListener::HandleEvent(int32_t event, TaiheFuncExecute execute)
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

void TaiheSessionListener::OnSessionCreate(const OHOS::AVSession::AVSessionDescriptor& descriptor)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnSessionCreate");
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    auto execute = [this, descriptor](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVSessionDescriptor descriptorTaihe = TaiheUtils::ToTaiheAVSessionDescriptor(descriptor);
        std::shared_ptr<taihe::callback<void(AVSessionDescriptor const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVSessionDescriptor const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(descriptorTaihe);
    };
    HandleEvent(EVENT_SESSION_CREATED, execute);
}

void TaiheSessionListener::OnSessionRelease(const OHOS::AVSession::AVSessionDescriptor& descriptor)
{
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    auto execute = [this, descriptor](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVSessionDescriptor descriptorTaihe = TaiheUtils::ToTaiheAVSessionDescriptor(descriptor);
        std::shared_ptr<taihe::callback<void(AVSessionDescriptor const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVSessionDescriptor const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(descriptorTaihe);
    };
    HandleEvent(EVENT_SESSION_DESTROYED, execute);
}

void TaiheSessionListener::OnTopSessionChange(const OHOS::AVSession::AVSessionDescriptor& descriptor)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnSessionCreate");
    SLOGI("sessionId=%{public}s", descriptor.sessionId_.c_str());
    auto execute = [this, descriptor](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVSessionDescriptor descriptorTaihe = TaiheUtils::ToTaiheAVSessionDescriptor(descriptor);
        std::shared_ptr<taihe::callback<void(AVSessionDescriptor const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVSessionDescriptor const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(descriptorTaihe);
    };
    HandleEvent(EVENT_TOP_SESSION_CHANGED, execute);
}

void TaiheSessionListener::OnAudioSessionChecked(const int32_t uid)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnAudioSessionCheck");
}

void TaiheSessionListener::OnDeviceAvailable(const OHOS::AVSession::OutputDeviceInfo& castOutputDeviceInfo)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnDeviceAvailable");
    SLOGI("Start handle device found event");
    ohos::multimedia::avsession::avSession::OutputDeviceInfo deviceInfoTaihe =
        TaiheUtils::ToTaiheOutputDeviceInfo(castOutputDeviceInfo);
    auto execute = [this, deviceInfoTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(
            ohos::multimedia::avsession::avSession::OutputDeviceInfo const&)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(
                ohos::multimedia::avsession::avSession::OutputDeviceInfo const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(deviceInfoTaihe);
    };
    HandleEvent(EVENT_DEVICE_AVAILABLE, execute);
}

void TaiheSessionListener::OnDeviceLogEvent(const OHOS::AVSession::DeviceLogEventCode eventId, const int64_t param)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnDeviceLogEvent");
    SLOGI("Start device log event");
    DeviceLogEventCode eventCodeTaihe = DeviceLogEventCode::from_value(static_cast<int32_t>(eventId));
    auto execute = [this, eventCodeTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(DeviceLogEventCode)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(DeviceLogEventCode)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(eventCodeTaihe);
    };
    HandleEvent(EVENT_DEVICE_LOG_EVENT, execute);
}

void TaiheSessionListener::OnDeviceOffline(const std::string& deviceId)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnDeviceOffline");
    SLOGI("Start handle device offline event");
    dataContext_.deviceId = string(deviceId);
    string_view deviceIdTaihe = dataContext_.deviceId;
    auto execute = [this, deviceIdTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(string_view)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(deviceIdTaihe);
    };
    HandleEvent(EVENT_DEVICE_OFFLINE, execute);
}

void TaiheSessionListener::OnDeviceStateChange(const OHOS::AVSession::DeviceState& deviceState)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnDeviceStateChange");
    SLOGI("Start handle device state changed event");
    DeviceState deviceStateTaihe = TaiheUtils::ToTaiheDeviceState(deviceState);
    std::weak_ptr<TaiheSessionListener> weakThis = shared_from_this();
    auto execute = [weakThis, deviceStateTaihe](std::shared_ptr<uintptr_t> method) {
        auto self = weakThis.lock();
        if (!self || !(self->isValid_) || !(*(self->isValid_))) {
            SLOGE("TaiheSessionListener is invalid");
            return;
        }
        std::shared_ptr<taihe::callback<void(DeviceState const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(DeviceState const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(deviceStateTaihe);
    };
    HandleEvent(EVENT_DEVICE_STATE_CHANGED, execute);
}

void TaiheSessionListener::OnRemoteDistributedSessionChange(
    const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheSessionListener::OnRemoteDistributedSessionChange");
    SLOGI("Start handle remote distributed session changed event");
    std::vector<std::shared_ptr<OHOS::AVSession::AVSessionController>> sessionControllersRef;
    for (auto& object: sessionControllers) {
        auto controllerObject = OHOS::iface_cast<OHOS::AVSession::IAVSessionController>(object);
        sessionControllersRef.push_back(std::shared_ptr<OHOS::AVSession::AVSessionController>(
            controllerObject.GetRefPtr(), [holder = controllerObject](const auto*) {}));
    }
    SLOGI("handle remote distributed session changed end size=%{public}d", (int) sessionControllersRef.size());
    dataContext_.sessionControllers =
        TaiheUtils::ToTaiheAVSessionControllerArray(sessionControllersRef);
    array_view<AVSessionController> sessionControllersRefTaihe = dataContext_.sessionControllers;
    auto execute = [this, sessionControllersRefTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(array_view<AVSessionController>)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(array_view<AVSessionController>)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(sessionControllersRefTaihe);
    };
    HandleEvent(EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED, execute);
}

int32_t TaiheSessionListener::AddCallback(int32_t event, std::shared_ptr<uintptr_t> ref)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], ref, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb == nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been registered");
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);

    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<TaiheAsyncCallback>(get_env(), mainHandler_);
    }
    callbacks_[event].push_back(ref);
    SLOGI("add callback %{public}d", static_cast<int32_t>(event));
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheSessionListener::RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> ref)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("remove callback %{public}d", static_cast<int32_t>(event));

    if (ref == nullptr) {
        for (auto& callbackRef : callbacks_[event]) {
            callbackRef = nullptr;
        }
        callbacks_[event].clear();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], ref, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb != nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been remove");
    callbacks_[event].remove(targetCb);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession