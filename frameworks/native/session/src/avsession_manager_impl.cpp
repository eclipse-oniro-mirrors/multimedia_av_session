/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "avsession_manager_impl.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_client.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"
#include "avsession_utils.h"

namespace OHOS::AVSession {
AVSessionManagerImpl::AVSessionManagerImpl()
{
    SLOGD("constructor");
}

sptr<AVSessionServiceProxy> AVSessionManagerImpl::GetService()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (service_) {
        return service_;
    }

    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("failed to get sa mgr");
        return nullptr;
    }
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGE("failed to get service");
        return nullptr;
    }
    service_ = iface_cast<AVSessionServiceProxy>(object);
    if (service_ != nullptr) {
        auto recipient = new(std::nothrow) ServiceDeathRecipient([this] { OnServiceDie(); });
        if (recipient == nullptr) {
            SLOGE("register ServiceDeathRecipient failed");
            return nullptr;
        }

        sptr<IAVSessionService> serviceBase = service_;
        serviceBase->AsObject()->AddDeathRecipient(recipient);

        SLOGD("get service success");
        RegisterClientDeathObserver();
    }
    return service_;
}

void AVSessionManagerImpl::OnServiceDie()
{
    SLOGI("enter");
    auto callback = deathCallback_;
    {
        std::lock_guard<std::mutex> lockGuard(lock_);
        service_.clear();
        listener_.clear();
        clientDeath_.clear();
        deathCallback_ = nullptr;
    }
    if (callback) {
        callback();
    }
    HISYSEVENT_RESET;
    HISYSEVENT_UNREGISTER;
    std::string cachePath(AVSessionUtils::GetCachePathName());
    AVSessionUtils::DeleteCacheFiles(cachePath);
}

std::shared_ptr<AVSession> AVSessionManagerImpl::CreateSession(const std::string& tag, int32_t type,
                                                               const AppExecFwk::ElementName& elementName)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::CreateSession");
    if (tag.empty() || elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        SLOGE("param is invalid");
        return nullptr;
    }
    if (type != AVSession::SESSION_TYPE_AUDIO && type != AVSession::SESSION_TYPE_VIDEO) {
        SLOGE("type is invalid");
        return nullptr;
    }

    auto service = GetService();
    return service ? service->CreateSession(tag, type, elementName) : nullptr;
}

int32_t AVSessionManagerImpl::GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors)
{
    auto service = GetService();
    return service ? service->GetAllSessionDescriptors(descriptors) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::GetActivatedSessionDescriptors(std::vector<AVSessionDescriptor>& activatedSessions)
{
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = GetAllSessionDescriptors(descriptors);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAllSessionDescriptors failed");

    for (const auto& descriptor : descriptors) {
        if (descriptor.isActive_) {
            activatedSessions.push_back(descriptor);
        }
    }
    return ret;
}

int32_t AVSessionManagerImpl::GetSessionDescriptorsBySessionId(const std::string& sessionId,
                                                               AVSessionDescriptor& descriptor)
{
    if (sessionId.empty()) {
        SLOGE("sessionId is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->GetSessionDescriptorsBySessionId(sessionId, descriptor) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::GetHistoricalSessionDescriptors(int32_t maxSize,
    std::vector<AVSessionDescriptor>& descriptors)
{
    auto service = GetService();
    return service ? service->GetHistoricalSessionDescriptors(maxSize, descriptors) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::CreateController(const std::string& sessionId,
    std::shared_ptr<AVSessionController>& controller)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::CreateController");
    if (sessionId.empty()) {
        SLOGE("sessionId is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->CreateController(sessionId, controller) : ERR_SERVICE_NOT_EXIST;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionManagerImpl::GetAVCastController(const std::string& sessionId,
    std::shared_ptr<AVCastController>& castController)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::GetAVCastController");
    if (sessionId.empty()) {
        SLOGE("sessionId is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->GetAVCastController(sessionId, castController) : ERR_SERVICE_NOT_EXIST;
}
#endif

int32_t AVSessionManagerImpl::RegisterSessionListener(const std::shared_ptr<SessionListener>& listener)
{
    if (listener == nullptr) {
        SLOGE("listener is nullptr");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    if (service == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }

    if (listener_ != nullptr) {
        return ERR_SESSION_LISTENER_EXIST;
    }

    listener_ = new(std::nothrow) SessionListenerClient(listener);
    if (listener_ == nullptr) {
        return ERR_NO_MEMORY;
    }
    auto ret = service->RegisterSessionListener(listener_);
    if (ret != AVSESSION_SUCCESS) {
        std::lock_guard<std::mutex> lockGuard(lock_);
        listener_.clear();
        return ret;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::RegisterServiceDeathCallback(const DeathCallback& callback)
{
    deathCallback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::UnregisterServiceDeathCallback()
{
    deathCallback_ = nullptr;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::SendSystemAVKeyEvent");
    if (!keyEvent.IsValid()) {
        SLOGE("keyEvent is invalid");
        return ERR_COMMAND_NOT_SUPPORT;
    }

    auto service = GetService();
    return service ? service->SendSystemAVKeyEvent(keyEvent) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::SendSystemControlCommand(const AVControlCommand& command)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::SendSystemControlCommand");
    if (!command.IsValid()) {
        SLOGE("command is invalid");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "INVALID_COMMAND", "CMD", command.GetCommand(),
            "ERROR_CODE", ERR_INVALID_PARAM, "ERROR_INFO", "avsessionmanagerimpl command is invalid");
        return ERR_COMMAND_NOT_SUPPORT;
    }

    auto service = GetService();
    if (service == nullptr) {
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "GET_SERVICE_ERROR",
            "ERROR_CODE", ERR_SERVICE_NOT_EXIST, "ERROR_INFO", "mgrimp sendsystemcontrolcommand get service error");
        return ERR_SERVICE_NOT_EXIST;
    }
    return service->SendSystemControlCommand(command);
}

int32_t AVSessionManagerImpl::CastAudio(const SessionToken& token,
                                        const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::CastAudio");
    CHECK_AND_RETURN_RET_LOG(descriptors.size() > 0, ERR_INVALID_PARAM, "devices size is zero");
    auto service = GetService();
    return service ? service->CastAudio(token, descriptors) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::CastAudioForAll");
    CHECK_AND_RETURN_RET_LOG(descriptors.size() > 0, ERR_INVALID_PARAM, "devices size is zero");
    auto service = GetService();
    return service ? service->CastAudioForAll(descriptors) : ERR_SERVICE_NOT_EXIST;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionManagerImpl::StartCastDiscovery(const int32_t castDeviceCapability)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::StartCastDiscovery");
    auto service = GetService();
    return service ? service->StartCastDiscovery(castDeviceCapability) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::StopCastDiscovery()
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::StopCastDiscovery");
    auto service = GetService();
    return service ? service->StopCastDiscovery() : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::StartCast");
    auto service = GetService();
    return service ? service->StartCast(sessionToken, outputDeviceInfo) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::StopCast(const SessionToken& sessionToken)
{
    AVSESSION_TRACE_SYNC_START("AVSessionManagerImpl::StopCast");
    auto service = GetService();
    return service ? service->StopCast(sessionToken) : ERR_SERVICE_NOT_EXIST;
}
#endif

void AVSessionManagerImpl::RegisterClientDeathObserver()
{
    clientDeath_ = new(std::nothrow) ClientDeathStub();
    if (clientDeath_ == nullptr) {
        SLOGE("malloc failed");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "MALLOC_FAILED",
            "ERROR_INFO", "avsession manager impl register client death observer malloc failed");
        return;
    }
    
    if (service_->RegisterClientDeathObserver(clientDeath_) != AVSESSION_SUCCESS) {
        SLOGE("register failed");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "REGISTER_FAILED",
            "ERROR_INFO", "avsession manager impl register client death observer register failed");
        return;
    }
    SLOGI("success");
}

ServiceDeathRecipient::ServiceDeathRecipient(const std::function<void()>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void ServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    if (callback_) {
        callback_();
    }
}
} // namespace OHOS::AVSession
