/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
        if (recipient != nullptr) {
            sptr<IAVSessionService> serviceBase = service_;
            serviceBase->AsObject()->AddDeathRecipient(recipient);
        }
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
}

std::shared_ptr<AVSession> AVSessionManagerImpl::CreateSession(const std::string &tag, int32_t type,
                                                               const AppExecFwk::ElementName& elementName)
{
    AVSessionTrace trace("AVSessionManagerImpl::CreateSession");
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
    AVSessionTrace trace("AVSessionManagerImpl::GetAllSessionDescriptors");
    auto service = GetService();
    return service ? service->GetAllSessionDescriptors(descriptors) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::GetActivatedSessionDescriptors(std::vector<AVSessionDescriptor>& activatedSessions)
{
    AVSessionTrace trace("AVSessionManagerImpl::GetActivatedSessionDescriptors");
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
    AVSessionTrace trace("AVSessionManagerImpl::GetSessionDescriptorsBySessionId");
    if (sessionId.empty()) {
        SLOGE("sessionId is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->GetSessionDescriptorsBySessionId(sessionId, descriptor) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::CreateController(const std::string& sessionId,
    std::shared_ptr<AVSessionController>& controller)
{
    AVSessionTrace trace("AVSessionManagerImpl::CreateController");
    if (sessionId.empty()) {
        SLOGE("sessionId is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->CreateController(sessionId, controller) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::RegisterSessionListener(const std::shared_ptr<SessionListener> &listener)
{
    AVSessionTrace trace("AVSessionManagerImpl::RegisterSessionListener");
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
        listener_.clear();
        return ret;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::RegisterServiceDeathCallback(const DeathCallback &callback)
{
    deathCallback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::UnregisterServiceDeathCallback()
{
    deathCallback_ = nullptr;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::SendSystemAVKeyEvent(const MMI::KeyEvent &keyEvent)
{
    AVSessionTrace trace("AVSessionManagerImpl::SendSystemAVKeyEvent");
    if (!keyEvent.IsValid()) {
        SLOGE("keyEvent is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->SendSystemAVKeyEvent(keyEvent) : ERR_SERVICE_NOT_EXIST;
}

int32_t AVSessionManagerImpl::SendSystemControlCommand(const AVControlCommand &command)
{
    AVSessionTrace trace("AVSessionManagerImpl::SendSystemControlCommand");
    if (!command.IsValid()) {
        SLOGE("command is invalid");
        return ERR_INVALID_PARAM;
    }

    auto service = GetService();
    return service ? service->SendSystemControlCommand(command) : ERR_SERVICE_NOT_EXIST;
}

void AVSessionManagerImpl::RegisterClientDeathObserver()
{
    AVSessionTrace trace("AVSessionManagerImpl::RegisterClientDeathObserver");
    clientDeath_ = new(std::nothrow) ClientDeathStub();
    if (clientDeath_ == nullptr) {
        SLOGE("malloc failed");
        return;
    }
    if (service_->RegisterClientDeathObserver(clientDeath_) != AVSESSION_SUCCESS) {
        SLOGE("register failed");
        return;
    }
    SLOGI("success");
}

ServiceDeathRecipient::ServiceDeathRecipient(const std::function<void()>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void ServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (callback_) {
        callback_();
    }
}
} // namespace OHOS::AVSession