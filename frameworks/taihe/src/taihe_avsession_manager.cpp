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
#define LOG_TAG "TaiheAVSessionManager"
#endif

#include "taihe_avsession_manager.h"

#include "ability.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_sysevent.h"
#include "avsession_trace.h"
#include "avsession_radar.h"
#include "avsession_info.h"
#include "ipc_skeleton.h"
#include "key_event.h"
#include "taihe_avcast_controller.h"
#include "taihe_avsession_controller.h"
#include "taihe_avsession.h"
#include "taihe_control_command.h"
#include "taihe_utils.h"
#include "taihe_avcast_picker_helper.h"
#include "tokenid_kit.h"
#include "permission_checker.h"

namespace ANI::AVSession {
using namespace OHOS::Security::AccessToken;
std::map<std::string, std::pair<TaiheAVSessionManager::OnEventHandlerType, TaiheAVSessionManager::OffEventHandlerType>>
    TaiheAVSessionManager::eventHandlers_ = {
    { "sessionCreate", { OnSessionCreate, OffSessionCreate } },
    { "sessionDestroy", { OnSessionDestroy, OffSessionDestroy } },
    { "topSessionChange", { OnTopSessionChange, OffTopSessionChange } },
    { "sessionServiceDie", { OnServiceDie, OffServiceDie } },
    { "deviceAvailable", { OnDeviceAvailable, OffDeviceAvailable } },
    { "deviceLogEvent", { OnDeviceLogEvent, OffDeviceLogEvent } },
    { "deviceOffline", { OnDeviceOffline, OffDeviceOffline } },
};

std::map<OHOS::AVSession::DistributedSessionType, std::pair<TaiheAVSessionManager::OnEventHandlerType,
    TaiheAVSessionManager::OffEventHandlerType>> TaiheAVSessionManager::distributedControllerEventHandlers_ = {
    { OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE, {
        OnRemoteDistributedSessionChange, OffRemoteDistributedSessionChange } },
};

const std::string TaiheAVSessionManager::DISTRIBUTED_SESSION_CHANGE_EVENT = "distributedSessionChange";

std::shared_ptr<TaiheSessionListener> TaiheAVSessionManager::listener_;
std::shared_ptr<TaiheAsyncCallback> TaiheAVSessionManager::asyncCallback_;
std::list<std::shared_ptr<uintptr_t>> TaiheAVSessionManager::serviceDiedCallbacks_;
std::shared_ptr<OHOS::AppExecFwk::EventHandler> TaiheAVSessionManager::mainHandler_;
std::mutex listenerMutex_;
std::mutex createControllerMutex_;
std::shared_ptr<AVSessionImpl> taiheSession = nullptr;

std::map<int32_t, int32_t> TaiheAVSessionManager::errcode_ = {
    {OHOS::AVSession::AVSESSION_ERROR, 6600101},
    {OHOS::AVSession::ERR_NO_MEMORY, 6600101},
    {OHOS::AVSession::ERR_SERVICE_NOT_EXIST, 6600101},
    {OHOS::AVSession::ERR_SESSION_LISTENER_EXIST, 6600101},
    {OHOS::AVSession::ERR_MARSHALLING, 6600101},
    {OHOS::AVSession::ERR_UNMARSHALLING, 6600101},
    {OHOS::AVSession::ERR_IPC_SEND_REQUEST, 6600101},
    {OHOS::AVSession::ERR_CONTROLLER_IS_EXIST, 6600101},
    {OHOS::AVSession::ERR_START_ABILITY_IS_RUNNING, 6600101},
    {OHOS::AVSession::ERR_ABILITY_NOT_AVAILABLE, 6600101},
    {OHOS::AVSession::ERR_START_ABILITY_TIMEOUT, 6600101},
    {OHOS::AVSession::ERR_SESSION_NOT_EXIST, 6600102},
    {OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST, 6600103},
    {OHOS::AVSession::ERR_RPC_SEND_REQUEST, 6600104},
    {OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT, 6600105},
    {OHOS::AVSession::ERR_SESSION_DEACTIVE, 6600106},
    {OHOS::AVSession::ERR_COMMAND_SEND_EXCEED_MAX, 6600107},
    {OHOS::AVSession::ERR_DEVICE_CONNECTION_FAILED, 6600108},
    {OHOS::AVSession::ERR_REMOTE_CONNECTION_NOT_EXIST, 6600109},
    {OHOS::AVSession::ERR_SESSION_IS_EXIST, 6600101},
    {OHOS::AVSession::ERR_PERMISSION_DENIED, 201},
    {OHOS::AVSession::ERR_NO_PERMISSION, 202},
    {OHOS::AVSession::ERR_INVALID_PARAM, 401},
};

void TaiheAVSessionManager::ExecuteCallback(std::shared_ptr<uintptr_t> method)
{
    std::shared_ptr<taihe::callback<void()>> cacheCallback =
        std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
    CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
    (*cacheCallback)();
}

void TaiheAVSessionManager::HandleServiceDied()
{
    if (!serviceDiedCallbacks_.empty() && asyncCallback_ != nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
            ++callbackRef) {
            asyncCallback_->Call(*callbackRef, [](std::shared_ptr<uintptr_t> method) {
                TaiheAVSessionManager::ExecuteCallback(method);
            });
        }
    }
    std::lock_guard lockGuard(listenerMutex_);
    if (listener_ != nullptr) {
        SLOGI("clear listener for service die");
        listener_ = nullptr;
    }
}

void TaiheAVSessionManager::HandleServiceStart()
{
    SLOGI("HandleServiceStart enter");
    if (taiheSession != nullptr) {
        std::shared_ptr<OHOS::AVSession::AVSession> session;
        int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().CreateSession(taiheSession->GetSessionTag(),
            TaiheUtils::ConvertSessionType(taiheSession->GetSessionTypeInner()),
            taiheSession->GetSessionElement(), session);
        SLOGI("HandleServiceStart CreateSession ret=%{public}d", ret);
        if (ret == OHOS::AVSession::AVSESSION_SUCCESS) {
            int32_t res = AVSessionImpl::ReCreateInstance(session);
            SLOGI("HandleServiceStart ReCreateInstance ret=%{public}d", res);
        }
    }
}

void TaiheAVSessionManager::ReportStartCastDiscoveryFailInfo(std::string func, int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info(func);
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToStartCastDiscovery(info);
}

void TaiheAVSessionManager::ReportStopCastDiscoveryFailInfo(std::string func, int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info(func);
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToStopCastDiscovery(info);
}

void TaiheAVSessionManager::ReportStartCastFailInfo(int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info("TaiheAVSessionManager::StartCast");
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToStartCast(info);
}

void TaiheAVSessionManager::ReportStartCastFailInfo(int32_t error,
    const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfo)
{
    OHOS::AVSession::AVSessionRadarInfo info("TaiheAVSessionManager::StartCast");
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToStartCast(outputDeviceInfo, info);
}

void TaiheAVSessionManager::ReportStopCastFailInfo(int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info("TaiheAVSessionManager::StopCast");
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToStopCast(info);
}

int32_t TaiheAVSessionManager::RegisterNativeSessionListener()
{
    std::lock_guard lockGuard(listenerMutex_);
    if (listener_ != nullptr) {
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    listener_ = std::make_shared<TaiheSessionListener>();
    if (OHOS::AVSession::AVSessionManager::GetInstance().RegisterServiceDeathCallback(HandleServiceDied) !=
        OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("register service death callback fail!");
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    if (listener_ == nullptr) {
        SLOGE("OnEvent failed : no memory");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_MEMORY],
            "OnEvent failed : no memory");
        return OHOS::AVSession::ERR_NO_MEMORY;
    }
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().RegisterSessionListener(listener_);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("native register session listener failed");
        if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "OnEvent failed : native invalid parameters");
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
                "OnEvent failed : native no permission");
        } else {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
                "OnEvent failed : native server exception");
        }
        return OHOS::AVSession::AVSESSION_ERROR;
    }

    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OnEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback)
{
    std::string eventName = event;
    int32_t err = OHOS::AVSession::PermissionChecker::GetInstance().CheckPermission(
        OHOS::AVSession::PermissionChecker::CHECK_SYSTEM_PERMISSION);
    CHECK_AND_RETURN_RET_LOG(err == OHOS::ERR_NONE, TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
        "Check system permission error");

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (RegisterNativeSessionListener() != OHOS::AVSession::AVSESSION_SUCCESS) {
        return OHOS::AVSession::AVSESSION_ERROR;
    }

    if (it->second.first(callback) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "add event callback failed");
    }

    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OffEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback)
{
    std::string eventName = event;
    int32_t err = OHOS::AVSession::PermissionChecker::GetInstance().CheckPermission(
        OHOS::AVSession::PermissionChecker::CHECK_SYSTEM_PERMISSION);
    CHECK_AND_RETURN_RET_LOG(err == OHOS::ERR_NONE, TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
        "Check system permission error");

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (it->second.second(callback) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "remove event callback failed");
    }

    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OnDistributedSessionChangeEvent(OHOS::AVSession::DistributedSessionType sessionType,
    std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("OnDistributedSessionChangeEvent");
    OHOS::AVSession::DistributedSessionType sessionType_ = sessionType;

    int32_t err = OHOS::AVSession::PermissionChecker::GetInstance().CheckPermission(
        OHOS::AVSession::PermissionChecker::CHECK_SYSTEM_PERMISSION);
    CHECK_AND_RETURN_RET_LOG(err == OHOS::ERR_NONE, TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
        "Check system permission error");
    CHECK_AND_RETURN_RET_LOG(sessionType_ >= OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE &&
        sessionType_ < OHOS::AVSession::DistributedSessionType::TYPE_SESSION_MAX,
        OHOS::AVSession::ERR_INVALID_PARAM, "GetDistributedSessionControllers invalid sessionType");

    auto it = distributedControllerEventHandlers_.find(sessionType_);
    if (it == distributedControllerEventHandlers_.end()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "session type invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (RegisterNativeSessionListener() != OHOS::AVSession::AVSESSION_SUCCESS) {
        return OHOS::AVSession::AVSESSION_ERROR;
    }

    if (it->second.first(callback) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "add event callback failed");
    }

    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OffDistributedSessionChangeEvent(OHOS::AVSession::DistributedSessionType sessionType,
    std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("OffDistributedSessionChangeEvent");
    OHOS::AVSession::DistributedSessionType sessionType_ = sessionType;

    int32_t err = OHOS::AVSession::PermissionChecker::GetInstance().CheckPermission(
        OHOS::AVSession::PermissionChecker::CHECK_SYSTEM_PERMISSION);
    CHECK_AND_RETURN_RET_LOG(err == OHOS::ERR_NONE, TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
        "Check system permission error");
    CHECK_AND_RETURN_RET_LOG(sessionType_ >= OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE &&
        sessionType_ < OHOS::AVSession::DistributedSessionType::TYPE_SESSION_MAX,
        OHOS::AVSession::ERR_INVALID_PARAM, "GetDistributedSessionControllers invalid sessionType");

    auto it = distributedControllerEventHandlers_.find(sessionType_);
    if (it == distributedControllerEventHandlers_.end()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "session type invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (it->second.second(callback) != napi_ok) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "remove event callback failed");
    }

    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OnSessionCreate(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_SESSION_CREATED, callback);
}

int32_t TaiheAVSessionManager::OnSessionDestroy(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_SESSION_DESTROYED, callback);
}

int32_t TaiheAVSessionManager::OnTopSessionChange(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

int32_t TaiheAVSessionManager::OnAudioSessionChecked(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

int32_t TaiheAVSessionManager::OnDeviceAvailable(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_DEVICE_AVAILABLE, callback);
}

int32_t TaiheAVSessionManager::OnDeviceLogEvent(std::shared_ptr<uintptr_t> &callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_DEVICE_LOG_EVENT, callback);
}

int32_t TaiheAVSessionManager::OnDeviceOffline(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_DEVICE_OFFLINE, callback);
}

int32_t TaiheAVSessionManager::OnServiceDie(std::shared_ptr<uintptr_t> &callback)
{
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        serviceDiedCallbacks_, callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb == nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been registered");
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<TaiheAsyncCallback>(get_env(), mainHandler_);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return OHOS::AVSession::AVSESSION_ERROR;
        }
    }
    serviceDiedCallbacks_.push_back(callback);
    SLOGI("do service die register when listener setup");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVSessionManager::OnRemoteDistributedSessionChange(std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("OnRemoteDistributedSessionChange AddCallback");
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->AddCallback(TaiheSessionListener::EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED, callback);
}

int32_t TaiheAVSessionManager::OffSessionCreate(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_SESSION_CREATED, callback);
}

int32_t TaiheAVSessionManager::OffSessionDestroy(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_SESSION_DESTROYED, callback);
}

int32_t TaiheAVSessionManager::OffTopSessionChange(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

int32_t TaiheAVSessionManager::OffAudioSessionChecked(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

int32_t TaiheAVSessionManager::OffDeviceAvailable(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_DEVICE_AVAILABLE, callback);
}

int32_t TaiheAVSessionManager::OffDeviceLogEvent(std::shared_ptr<uintptr_t> &callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_DEVICE_LOG_EVENT, callback);
}

int32_t TaiheAVSessionManager::OffDeviceOffline(std::shared_ptr<uintptr_t> &callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_DEVICE_OFFLINE, callback);
}

int32_t TaiheAVSessionManager::OffRemoteDistributedSessionChange(std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("OffRemoteDistributedSessionChange RemoveCallback");
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "callback has not been registered");
    return listener_->RemoveCallback(TaiheSessionListener::EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED, callback);
}

int32_t TaiheAVSessionManager::OffServiceDie(std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("OffServiceDie but no longer UnregisterServiceDeathCallback");
    if (callback == nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            *callbackRef = nullptr;
        }
        serviceDiedCallbacks_.clear();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        serviceDiedCallbacks_, callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb != nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been remove");
    serviceDiedCallbacks_.remove(targetCb);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

struct AVSession CreateAVSessionSync(uintptr_t context, string_view tag, string_view type)
{
    OHOS::AVSession::AVSessionTrace trace("CreateAVSessionSync");
    struct AVSession undefinedAVSession = make_holder<AVSessionImpl, struct AVSession>();
    OHOS::AppExecFwk::ElementName elementName;
    if (TaiheUtils::GetStageElementName(context, elementName) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM], "invalid context");
        return undefinedAVSession;
    }
    std::string tagString;
    if (TaiheUtils::GetString(tag, tagString) != OHOS::AVSession::AVSESSION_SUCCESS || tagString.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM], "invalid tag");
        return undefinedAVSession;
    }
    std::string typeString;
    if (TaiheUtils::GetString(type, typeString) != OHOS::AVSession::AVSESSION_SUCCESS || typeString.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM], "invalid type");
        return undefinedAVSession;
    }
    int32_t typeInt = TaiheUtils::ConvertSessionType(typeString);
    if (typeInt < 0) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "wrong session type");
        return undefinedAVSession;
    }

    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().RegisterServiceStartCallback(
        TaiheAVSessionManager::HandleServiceStart);
    SLOGI("RegisterServiceStartCallback res=%{public}d", ret);

    std::shared_ptr<OHOS::AVSession::AVSession> session;
    ret = OHOS::AVSession::AVSessionManager::GetInstance().CreateSession(tagString, typeInt, elementName, session);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = (ret == OHOS::AVSession::ERR_SESSION_IS_EXIST) ?
            "CreateAVSession failed: session is existed" : "CreateAVSession failed: native create session failed";
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedAVSession;
    }

    struct AVSession output = make_holder<AVSessionImpl, struct AVSession>();
    ret = AVSessionImpl::NewInstance(session, output, taiheSession, tagString, elementName);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedAVSession;
    }
    return output;
}

array<AVSessionDescriptor> GetAllSessionDescriptorsSync()
{
    std::vector<AVSessionDescriptor> emptyResult;
    std::vector<OHOS::AVSession::AVSessionDescriptor> descriptors;
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAllSessionDescriptors failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAllSessionDescriptors failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "GetAllSessionDescriptors failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<AVSessionDescriptor>(emptyResult);
    }
    return TaiheUtils::ToTaiheAVSessionDescriptorArray(descriptors);
}

array<AVSessionDescriptor> GetHistoricalSessionDescriptorsSync(int32_t maxSize)
{
    std::vector<AVSessionDescriptor> emptyResult;
    if (maxSize > TaiheAVSessionManager::HISTORICAL_MAX_NUM || maxSize < TaiheAVSessionManager::HISTORICAL_MIN_NUM) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "invalid arguments");
        return array<AVSessionDescriptor>(emptyResult);
    }

    std::vector<OHOS::AVSession::AVSessionDescriptor> descriptors;
    int32_t ret =
        OHOS::AVSession::AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(maxSize, descriptors);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetHistoricalSessionDescriptors failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetHistoricalSessionDescriptors failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "GetHistoricalSessionDescriptors failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<AVSessionDescriptor>(emptyResult);
    }
    return TaiheUtils::ToTaiheAVSessionDescriptorArray(descriptors);
}

array<AVSessionDescriptor> GetHistoricalSessionDescriptorsOptionalSync(optional_view<int32_t> maxSize)
{
    int32_t maxSizeInner = maxSize.has_value() ? maxSize.value() : TaiheAVSessionManager::HISTORICAL_UNSET_NUM;
    return GetHistoricalSessionDescriptorsSync(maxSizeInner);
}

array<AVQueueInfo> GetHistoricalAVQueueInfosSync(int32_t maxSize, int32_t maxAppSize)
{
    std::vector<AVQueueInfo> emptyResult;
    std::vector<OHOS::AVSession::AVQueueInfo> avQueueInfos;
    int32_t ret =
        OHOS::AVSession::AVSessionManager::GetInstance().GetHistoricalAVQueueInfos(maxSize, maxAppSize, avQueueInfos);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetHistoricalAVQueueInfos failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetHistoricalAVQueueInfos failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "GetHistoricalAVQueueInfos failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<AVQueueInfo>(emptyResult);
    }
    return TaiheUtils::ToTaiheAVQueueInfoArray(avQueueInfos);
}

AVSessionController CreateControllerSync(string_view sessionId)
{
    OHOS::AVSession::AVSessionTrace trace("CreateControllerSync");
    AVSessionController undefinedController = make_holder<AVSessionControllerImpl, AVSessionController>();
    std::string sessionIdString;
    if (TaiheUtils::GetString(sessionId, sessionIdString) != OHOS::AVSession::AVSESSION_SUCCESS ||
        sessionIdString.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "invalid sessionId");
        return undefinedController;
    }

    std::shared_ptr<OHOS::AVSession::AVSessionController> controller;
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().CreateController(sessionIdString, controller);
    SLOGI("check create controller with errCode %{public}d", ret);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS && ret != OHOS::AVSession::ERR_CONTROLLER_IS_EXIST) {
        std::string errMessage = "CreateController failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "CreateController failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "CreateController failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "CreateController failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "CreateController failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_IS_EXIST) {
            errMessage = "create controller with already has one";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedController;
    }

    std::lock_guard lockGuard(createControllerMutex_);
    AVSessionController output = make_holder<AVSessionControllerImpl, AVSessionController>();
    int32_t retInstance = OHOS::AVSession::AVSESSION_ERROR;
    if (ret == OHOS::AVSession::ERR_CONTROLLER_IS_EXIST) {
        retInstance = AVSessionControllerImpl::RepeatedInstance(sessionIdString, output);
    } else {
        retInstance = AVSessionControllerImpl::NewInstance(controller, output);
    }
    if (retInstance != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedController;
    }
    return output;
}

void StartAVPlaybackSync(string_view bundleName, string_view assetId)
{
    std::string bundleNameInner;
    if (TaiheUtils::GetString(bundleName, bundleNameInner) != OHOS::AVSession::AVSESSION_SUCCESS ||
        bundleNameInner.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartAVPlayback invalid bundlename");
        return;
    }
    std::string assetIdInner;
    if (TaiheUtils::GetString(assetId, assetIdInner) != OHOS::AVSession::AVSESSION_SUCCESS || assetIdInner.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartAVPlayback invalid assetId");
        return;
    }

    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StartAVPlayback(bundleNameInner, assetIdInner);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StartAVPlayback failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "StartAVPlayback failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "StartAVPlayback failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

optional<AVCastController> GetAVCastControllerSync(string_view sessionId)
{
    optional<AVCastController> undefinedCastController = optional<AVCastController>(std::nullopt);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::GetAVCastControllerSync");
    std::string sessionIdInner;
    if (TaiheUtils::GetString(sessionId, sessionIdInner) != OHOS::AVSession::AVSESSION_SUCCESS ||
        sessionIdInner.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "invalid sessionId");
        return undefinedCastController;
    }

    std::shared_ptr<OHOS::AVSession::AVCastController> castController;
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().GetAVCastController(sessionIdInner, castController);
    SLOGI("check GetAVCastController with errCode %{public}d", ret);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVCastController failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVCastController failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "GetAVCastController failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "GetAVCastController failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVCastController failed : native session not exist";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedCastController;
    }

    AVCastController output = make_holder<AVCastControllerImpl, AVCastController>();
    int32_t retInstance = AVCastControllerImpl::NewInstance(castController, output);
    if (retInstance != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedCastController;
    }
    return optional<AVCastController>(std::in_place, output);
#else
    return undefinedCastController;
#endif
}

void StartCastingSync(SessionToken const &session, OutputDeviceInfo const &device)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StartCastingSync");
    OHOS::AVSession::SessionToken sessionToken;
    if (TaiheUtils::GetSessionToken(session, sessionToken) != OHOS::AVSession::AVSESSION_SUCCESS ||
        sessionToken.sessionId.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartCastingSync invalid session token");
        return;
    }
    OHOS::AVSession::OutputDeviceInfo outputDeviceInfo;
    if (TaiheUtils::GetOutputDeviceInfo(device, outputDeviceInfo) != OHOS::AVSession::AVSESSION_SUCCESS ||
        outputDeviceInfo.deviceInfos_.size() == 0) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartCastingSync invalid outputDeviceInfo");
        return;
    }

    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StartCast(sessionToken, outputDeviceInfo);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StartCast failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "StartCast failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "StartCast failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "StartCast failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "StartCast failed : native session not exist";
        }
        TaiheAVSessionManager::ReportStartCastFailInfo(ret, outputDeviceInfo);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

void StopCastingSync(SessionToken const &session)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StopCastingSync");
    OHOS::AVSession::SessionToken sessionToken;
    if (TaiheUtils::GetSessionToken(session, sessionToken) != OHOS::AVSession::AVSESSION_SUCCESS ||
        sessionToken.sessionId.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StopCastingSync invalid session token");
        return;
    }

    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StopCast(sessionToken);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StopCast failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "StopCast failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "StopCast failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "StopCast failed : native session not exist";
        }
        TaiheAVSessionManager::ReportStopCastFailInfo(ret);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
static void StartCastDeviceDiscoveryInner(int32_t castDeviceCapability, std::vector<std::string> &drmSchemes)
{
    int32_t ret =
        OHOS::AVSession::AVSessionManager::GetInstance().StartCastDiscovery(castDeviceCapability, drmSchemes);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StartCastDiscovery failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "StartCastDiscovery failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "StartCastDiscovery failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "StartCastDiscovery failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "StartCastDiscovery failed : native session not exist";
        }
        TaiheAVSessionManager::ReportStartCastDiscoveryFailInfo("TaiheAVSessionManager::StartCastDiscovery", ret);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}
#endif

void StartCastDeviceDiscoverySync()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StartCastDeviceDiscoverySync");
    int32_t castDeviceCapability = OHOS::AVSession::ProtocolType::TYPE_CAST_PLUS_STREAM;
    std::vector<std::string> drmSchemes;

    StartCastDeviceDiscoveryInner(castDeviceCapability, drmSchemes);
#endif
}

void StartCastDeviceDiscoveryFilter(int32_t filter)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StartCastDeviceDiscoveryFilter");
    int32_t castDeviceCapability = filter;
    std::vector<std::string> drmSchemes;

    StartCastDeviceDiscoveryInner(castDeviceCapability, drmSchemes);
#endif
}

void StartCastDeviceDiscoveryFilterDrm(optional_view<int32_t> filter, optional_view<array<string>> drmSchemes)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StartCastDeviceDiscoveryFilterDrm");
    int32_t castDeviceCapability = filter.has_value() ?
        filter.value() : OHOS::AVSession::ProtocolType::TYPE_CAST_PLUS_STREAM;

    std::vector<std::string> drmSchemesInner;
    if (drmSchemes.has_value() &&
        TaiheUtils::GetStringArray(drmSchemes.value(), drmSchemesInner) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheAVSessionManager::ReportStartCastDiscoveryFailInfo(
            "TaiheAVSessionManager::StartCastDeviceDiscoveryFilterDrm", OHOS::AVSession::ERR_INVALID_PARAM);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "invalid drmSchemes");
        return;
    }

    StartCastDeviceDiscoveryInner(castDeviceCapability, drmSchemesInner);
#endif
}

void StopCastDeviceDiscoverySync()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StopCastDeviceDiscoverySync");
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StopCastDiscovery();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StopCastDiscovery failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "StopCastDiscovery failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "StopCastDiscovery failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "StopCastDiscovery failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "StopCastDiscovery failed : native session not exist";
        }
        TaiheAVSessionManager::ReportStopCastDiscoveryFailInfo("TaiheAVSessionManager::StopCastDiscovery", ret);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

void SetDiscoverableSync(bool enable)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::SetDiscoverableSync");
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().SetDiscoverable(enable);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetDiscoverable failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetDiscoverable failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetDiscoverable failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetDiscoverable failed : native session not exist";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

static bool ParseCastAudioSessionType(CastAudioSessionType const& session,
    OHOS::AVSession::SessionToken &sessionToken, bool &isAll)
{
    int32_t ret = OHOS::AVSession::AVSESSION_ERROR;
    if (session.get_tag() == CastAudioSessionType::tag_t::typeAll) {
        std::string flag;
        ret = TaiheUtils::GetString(session.get_typeAll_ref(), flag);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS || flag != "all") {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "CastAudioSync invalid argument");
            return false;
        }
        isAll = true;
    } else if (session.get_tag() == CastAudioSessionType::tag_t::typeSessionToken) {
        ret = TaiheUtils::GetSessionToken(session.get_typeSessionToken_ref(), sessionToken);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS || sessionToken.sessionId.empty()) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "CastAudioSync invalid session token");
            return false;
        }
    }
    return true;
}

void CastAudioSync(CastAudioSessionType const& session, array_view<uintptr_t> audioDevices)
{
    OHOS::AVSession::AVSessionTrace trace("CastAudioSync");
    OHOS::AVSession::SessionToken sessionToken {};
    bool isAll = false;
    if (!ParseCastAudioSessionType(session, sessionToken, isAll)) {
        SLOGE("CastAudioSync ParseCastAudioSessionType failed");
        return;
    }

    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors;
    int32_t ret = TaiheUtils::GetAudioDeviceDescriptors(audioDevices, audioDeviceDescriptors);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS || audioDeviceDescriptors.size() == 0) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "CastAudioSync invalid AudioDeviceDescriptor");
        return;
    }

    ret = OHOS::AVSession::AVSESSION_ERROR;
    if (isAll) {
        ret = OHOS::AVSession::AVSessionManager::GetInstance().CastAudioForAll(audioDeviceDescriptors);
    } else {
        ret = OHOS::AVSession::AVSessionManager::GetInstance().CastAudio(sessionToken, audioDeviceDescriptors);
    }
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "CastAudioSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "CastAudioSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "CastAudioSync failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "CastAudioSync failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "CastAudioSync failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

array<AVSessionController> GetDistributedSessionControllerSync(DistributedSessionType distributedSessionType)
{
    SLOGI("GetDistributedSessionControllerSync");
    std::vector<std::shared_ptr<OHOS::AVSession::AVSessionController>> controllers;
    std::vector<AVSessionController> emptyControllers;
    int32_t err = OHOS::AVSession::PermissionChecker::GetInstance().CheckPermission(
        OHOS::AVSession::PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != OHOS::ERR_NONE) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_PERMISSION],
            "Check system permission error");
        return array<AVSessionController>(emptyControllers);
    }
    if (distributedSessionType < OHOS::AVSession::DistributedSessionType::TYPE_SESSION_REMOTE ||
        distributedSessionType >= OHOS::AVSession::DistributedSessionType::TYPE_SESSION_MAX) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "GetDistributedSessionControllerSync invalid sessionType");
        return array<AVSessionController>(emptyControllers);
    }
    OHOS::AVSession::DistributedSessionType sessionType =
        static_cast<OHOS::AVSession::DistributedSessionType>(distributedSessionType.get_value());
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().GetDistributedSessionControllers(
        sessionType, controllers);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetDistributedSessionControllerSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetDistributedSessionControllerSync failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "GetDistributedSessionControllerSync failed : native permission denied";
        } else if (ret == OHOS::AVSession::ERR_REMOTE_CONNECTION_NOT_EXIST) {
            errMessage = "GetDistributedSessionControllerSync failed : connect not exist";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<AVSessionController>(emptyControllers);
    }
    return TaiheUtils::ToTaiheAVSessionControllerArray(controllers);
}

void SendSystemAVKeyEventSync(keyEvent::KeyEvent const &event)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::SendSystemAVKeyEventSync");
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr = OHOS::MMI::KeyEvent::Create();
    CHECK_RETURN_VOID(keyEventPtr != nullptr, "SendAVKeyEventSync failed : create KeyEvent failed");
    OHOS::MMI::KeyEvent keyEvent = *keyEventPtr;
    if (TaiheUtils::GetKeyEvent(event, keyEvent) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendSystemAVKeyEventSync invalid key event");
        return;
    }
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().SendSystemAVKeyEvent(keyEvent);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendSystemAVKeyEventSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "SendSystemAVKeyEventSync failed : native invalid keyEvent";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendSystemAVKeyEventSync failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "SendSystemAVKeyEventSync failed : native permission denied";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void SendSystemControlCommandSync(AVControlCommand command)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::SendSystemControlCommandSync");
    OHOS::AVSession::AVControlCommand controlCommand = OHOS::AVSession::AVControlCommand();
    if (TaiheControlCommand::GetValue(command, controlCommand) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendSystemControlCommandSync invalid control command");
        return;
    }
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().SendSystemControlCommand(controlCommand);
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    double speed;
    int64_t time;
    int32_t mode;
    std::string assetId;
    controlCommand.GetSpeed(speed);
    controlCommand.GetSeekTime(time);
    controlCommand.GetLoopMode(mode);
    controlCommand.GetAssetId(assetId);
    {
        using namespace OHOS::AVSession;
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "SEND_CMD_FAILED",
            "CMD", controlCommand.GetCommand(), "TIME", time, "SPEED", speed, "MODE", mode, "ASSETID", assetId,
            "ERROR_CODE", ret, "ERROR_INFO", "native send control command failed");
    }
#endif
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendSystemControlCommandSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "SendSystemControlCommandSync failed : native invalid command";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendSystemControlCommandSync failed : native send control command no permission";
            {
                using namespace OHOS::AVSession;
                HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "ERROR_CODE", ret,
                    "ERROR_INFO", "SendSystemControlCommandSync failed : native no permission");
            }
        } else if (ret == OHOS::AVSession::ERR_PERMISSION_DENIED) {
            errMessage = "SendSystemControlCommandSync failed : native send control command permission denied";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_SEND_EXCEED_MAX) {
            errMessage = "SendSystemControlCommandSync failed : native send command overload";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

static bool JudgeNumString(std::string str)
{
    SLOGI("enter JudgeNumString");
    if (str.empty()) {
        return false;
    }

    int minNumChar = 48;
    int maxNumChar = 57;
    for (int i = 0; i < static_cast<int>(str.size()); i++) {
        if (str[i] < minNumChar || str[i] > maxNumChar) {
            return false;
        }
    }
    return true;
}

void StartDeviceLoggingSync(string_view url, optional_view<int32_t> maxSize)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::string fd;
    uint32_t maxSize_;
    if (TaiheUtils::GetString(url, fd) != OHOS::AVSession::AVSESSION_SUCCESS || fd.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartDeviceLoggingSync invalid url");
        return;
    }
    if (JudgeNumString(fd) == false) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartDeviceLoggingSync fd is not a num string");
        return;
    }
    if (maxSize.has_value()) {
        maxSize_ = maxSize.value();
        int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StartDeviceLogging(std::stoi(fd), maxSize_);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            std::string errMessage = "StopDeviceLoggingSync failed : return error code = " + std::to_string(ret);
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
            return;
        }
    }
#endif
}

void StopDeviceLoggingSync()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OHOS::AVSession::AVSessionTrace trace("TaiheAVSessionManager::StopDeviceLoggingSync");
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().StopDeviceLogging();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "StopDeviceLoggingSync failed : return error code = " + std::to_string(ret);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

keyEvent::KeyEvent CreateAVKeyEventSync(int64_t nativePtr)
{
    inputEvent::InputEvent undefinedInputEvent = {
        .id = 0,
        .deviceId = 0,
        .actionTime = 0,
        .screenId = 0,
        .windowId = 0,
    };
    keyEvent::Key undefinedKey = {
        .code = keyCode::KeyCode::from_value(0),
        .pressedTime = 0,
        .deviceId = 0,
    };
    std::vector<keyEvent::Key> emptyKeys;
    keyEvent::KeyEvent undefinedKeyEvent = {
        .base = undefinedInputEvent,
        .action = keyEvent::Action::from_value(0),
        .key = undefinedKey,
        .unicodeChar = 0,
        .keys = taihe::array<keyEvent::Key>(emptyKeys),
        .ctrlKey = false,
        .altKey = false,
        .shiftKey = false,
        .logoKey = false,
        .fnKey = false,
        .capsLock = false,
        .numLock = false,
        .scrollLock = false,
    };
    CHECK_RETURN(nativePtr != 0, "Invalid nativePtr", undefinedKeyEvent);
    OHOS::MMI::KeyEvent *keyEventPtr = reinterpret_cast<OHOS::MMI::KeyEvent*>(nativePtr);
    CHECK_RETURN(keyEventPtr != nullptr, "keyEventPtr is nullptr", undefinedKeyEvent);
    return TaiheUtils::ToTaiheKeyEvent(*keyEventPtr);
}

void OnDistributedSessionChange(DistributedSessionType param,
    callback_view<void(array_view<AVSessionController>)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    auto sessionType = static_cast<OHOS::AVSession::DistributedSessionType>(param.get_value());
    TaiheAVSessionManager::OnDistributedSessionChangeEvent(sessionType, cacheCallback);
}

void OnSessionCreate(callback_view<void(AVSessionDescriptor const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("sessionCreate", cacheCallback);
}

void OnSessionDestroy(callback_view<void(AVSessionDescriptor const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("sessionDestroy", cacheCallback);
}

void OnTopSessionChange(callback_view<void(AVSessionDescriptor const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("topSessionChange", cacheCallback);
}

void OnSessionServiceDie(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("sessionServiceDie", cacheCallback);
}

void OnDeviceAvailable(callback_view<void(OutputDeviceInfo const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("deviceAvailable", cacheCallback);
}

void OnDeviceLogEvent(callback_view<void(DeviceLogEventCode)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("deviceLogEvent", cacheCallback);
}

void OnDeviceOffline(callback_view<void(string_view)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    TaiheAVSessionManager::OnEvent("deviceOffline", cacheCallback);
}

void OffDistributedSessionChange(DistributedSessionType param,
    optional_view<callback<void(array_view<AVSessionController>)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    auto sessionType = static_cast<OHOS::AVSession::DistributedSessionType>(param.get_value());
    TaiheAVSessionManager::OffDistributedSessionChangeEvent(sessionType, cacheCallback);
}

void OffSessionCreate(optional_view<callback<void(AVSessionDescriptor const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("sessionCreate", cacheCallback);
}

void OffSessionDestroy(optional_view<callback<void(AVSessionDescriptor const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("sessionDestroy", cacheCallback);
}

void OffTopSessionChange(optional_view<callback<void(AVSessionDescriptor const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("topSessionChange", cacheCallback);
}

void OffSessionServiceDie(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("sessionServiceDie", cacheCallback);
}

void OffDeviceAvailable(optional_view<callback<void(OutputDeviceInfo const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("deviceAvailable", cacheCallback);
}

void OffDeviceLogEvent(optional_view<callback<void(DeviceLogEventCode)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("deviceLogEvent", cacheCallback);
}

void OffDeviceOffline(optional_view<callback<void(string_view)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    TaiheAVSessionManager::OffEvent("deviceOffline", cacheCallback);
}

AVCastPickerHelperInner CreateAVCastPickerHelperInnerSync(uintptr_t context)
{
    AVCastPickerHelperInner output = make_holder<AVCastPickerHelperInnerImpl, AVCastPickerHelperInner>();
    auto ret = AVCastPickerHelperInnerImpl::NewInstance(context, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        AVCastPickerHelperInner undefinedPickerHelperInner =
            make_holder<AVCastPickerHelperInnerImpl, AVCastPickerHelperInner>();
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedPickerHelperInner;
    }
    return output;
}
} // namespace ANI::AVSession

TH_EXPORT_CPP_API_CreateAVCastPickerHelperInnerSync(ANI::AVSession::CreateAVCastPickerHelperInnerSync);
TH_EXPORT_CPP_API_CreateAVSessionSync(ANI::AVSession::CreateAVSessionSync);
TH_EXPORT_CPP_API_GetAllSessionDescriptorsSync(ANI::AVSession::GetAllSessionDescriptorsSync);
TH_EXPORT_CPP_API_GetHistoricalSessionDescriptorsSync(ANI::AVSession::GetHistoricalSessionDescriptorsSync);
TH_EXPORT_CPP_API_GetHistoricalSessionDescriptorsOptionalSync(
    ANI::AVSession::GetHistoricalSessionDescriptorsOptionalSync);
TH_EXPORT_CPP_API_GetHistoricalAVQueueInfosSync(ANI::AVSession::GetHistoricalAVQueueInfosSync);
TH_EXPORT_CPP_API_CreateControllerSync(ANI::AVSession::CreateControllerSync);
TH_EXPORT_CPP_API_StartAVPlaybackSync(ANI::AVSession::StartAVPlaybackSync);
TH_EXPORT_CPP_API_GetAVCastControllerSync(ANI::AVSession::GetAVCastControllerSync);
TH_EXPORT_CPP_API_StartCastingSync(ANI::AVSession::StartCastingSync);
TH_EXPORT_CPP_API_StopCastingSync(ANI::AVSession::StopCastingSync);
TH_EXPORT_CPP_API_StartCastDeviceDiscoverySync(ANI::AVSession::StartCastDeviceDiscoverySync);
TH_EXPORT_CPP_API_StartCastDeviceDiscoveryFilter(ANI::AVSession::StartCastDeviceDiscoveryFilter);
TH_EXPORT_CPP_API_StartCastDeviceDiscoveryFilterDrm(ANI::AVSession::StartCastDeviceDiscoveryFilterDrm);
TH_EXPORT_CPP_API_StopCastDeviceDiscoverySync(ANI::AVSession::StopCastDeviceDiscoverySync);
TH_EXPORT_CPP_API_SetDiscoverableSync(ANI::AVSession::SetDiscoverableSync);
TH_EXPORT_CPP_API_CastAudioSync(ANI::AVSession::CastAudioSync);
TH_EXPORT_CPP_API_GetDistributedSessionControllerSync(ANI::AVSession::GetDistributedSessionControllerSync);
TH_EXPORT_CPP_API_SendSystemAVKeyEventSync(ANI::AVSession::SendSystemAVKeyEventSync);
TH_EXPORT_CPP_API_SendSystemControlCommandSync(ANI::AVSession::SendSystemControlCommandSync);
TH_EXPORT_CPP_API_StartDeviceLoggingSync(ANI::AVSession::StartDeviceLoggingSync);
TH_EXPORT_CPP_API_StopDeviceLoggingSync(ANI::AVSession::StopDeviceLoggingSync);
TH_EXPORT_CPP_API_CreateAVKeyEventSync(ANI::AVSession::CreateAVKeyEventSync);
TH_EXPORT_CPP_API_OnDistributedSessionChange(ANI::AVSession::OnDistributedSessionChange);
TH_EXPORT_CPP_API_OnSessionCreate(ANI::AVSession::OnSessionCreate);
TH_EXPORT_CPP_API_OnSessionDestroy(ANI::AVSession::OnSessionDestroy);
TH_EXPORT_CPP_API_OnTopSessionChange(ANI::AVSession::OnTopSessionChange);
TH_EXPORT_CPP_API_OnSessionServiceDie(ANI::AVSession::OnSessionServiceDie);
TH_EXPORT_CPP_API_OnDeviceAvailable(ANI::AVSession::OnDeviceAvailable);
TH_EXPORT_CPP_API_OnDeviceLogEvent(ANI::AVSession::OnDeviceLogEvent);
TH_EXPORT_CPP_API_OnDeviceOffline(ANI::AVSession::OnDeviceOffline);
TH_EXPORT_CPP_API_OffDistributedSessionChange(ANI::AVSession::OffDistributedSessionChange);
TH_EXPORT_CPP_API_OffSessionCreate(ANI::AVSession::OffSessionCreate);
TH_EXPORT_CPP_API_OffSessionDestroy(ANI::AVSession::OffSessionDestroy);
TH_EXPORT_CPP_API_OffTopSessionChange(ANI::AVSession::OffTopSessionChange);
TH_EXPORT_CPP_API_OffSessionServiceDie(ANI::AVSession::OffSessionServiceDie);
TH_EXPORT_CPP_API_OffDeviceAvailable(ANI::AVSession::OffDeviceAvailable);
TH_EXPORT_CPP_API_OffDeviceLogEvent(ANI::AVSession::OffDeviceLogEvent);
TH_EXPORT_CPP_API_OffDeviceOffline(ANI::AVSession::OffDeviceOffline);