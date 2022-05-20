/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

namespace OHOS::AVSession {
AVSessionManagerImpl::DeathRecipientImpl::DeathRecipientImpl(const DeathCallback& callback)
    : callback_(callback)
{
    SLOGI("construct");
}

AVSessionManagerImpl::DeathRecipientImpl::~DeathRecipientImpl()
{
    SLOGI("destroy");
}

void AVSessionManagerImpl::DeathRecipientImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    SLOGI("enter");
    if (callback_) {
        callback_();
    }
}

AVSessionManagerImpl& AVSessionManagerImpl::GetInstance()
{
    static AVSessionManagerImpl instance;
    return instance;
}

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

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        SLOGE("failed to get samgr");
        return nullptr;
    }
    auto object = samgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGE("failed to get avsession service");
        return nullptr;
    }
    service_ = iface_cast<AVSessionServiceProxy>(object);
    if (service_ != nullptr) {
        auto recipient = new(std::nothrow) DeathRecipientImpl([this] { OnServiceDied(); });
        if (recipient != nullptr) {
            sptr<IAVSessionService> serviceBase = service_;
            serviceBase->AsObject()->AddDeathRecipient(recipient);
        }
    }
    SLOGD("get avsession service success");
    return service_;
}


void AVSessionManagerImpl::OnServiceDied()
{
    SLOGI("enter");
    auto callback = deathCallback_;
    {
        std::lock_guard<std::mutex> lockGuard(lock_);
        service_ = nullptr;
        listener_ = nullptr;
        deathCallback_ = nullptr;
    }
    if (callback) {
        callback();
    }
}

std::shared_ptr<AVSession> AVSessionManagerImpl::CreateSession(const std::string &tag, int32_t type,
    const std::string &bundleName, const std::string &abilityName)
{
    auto service = GetService();
    return service ? service->CreateSession(tag, type, bundleName, abilityName) : nullptr;
}

std::shared_ptr<AVSession> AVSessionManagerImpl::GetSession()
{
    return nullptr;
}

std::vector<AVSessionDescriptor> AVSessionManagerImpl::GetAllSessionDescriptors()
{
    return {};
}

std::shared_ptr<AVSessionController> AVSessionManagerImpl::CreateController(int32_t sessionld)
{
    return nullptr;
}

std::shared_ptr<AVSessionController> AVSessionManagerImpl::GetController(int32_t sessionld)
{
    return nullptr;
}

std::vector<std::shared_ptr<AVSessionController>> AVSessionManagerImpl::GetAllControllers()
{
    return nullptr;
}

int32_t AVSessionManagerImpl::RegisterSessionListener(std::shared_ptr<SessionListener> &listener)
{
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
    if (service->RegisterSessionListener(listener_) != AVSESSION_SUCCESS) {
        listener_.clear();
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::RegisterServiceDeathCallback(const DeathCallback &callback)
{
    deathCallback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::SendSystemMediaKeyEvent(MMI::KeyEvent &keyEvent)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::SetSystemMediaVolume(int32_t volume)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManagerImpl::RegesterClientDeathObserver()
{
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession