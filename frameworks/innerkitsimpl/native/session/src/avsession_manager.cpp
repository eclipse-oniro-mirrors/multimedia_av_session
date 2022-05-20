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

#include "avsession_manager.h"
#include "avsession_manager_impl.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
std::shared_ptr<AVSession> AVSessionManager::CreateSession(const std::string &tag, int32_t type,
                                                           const std::string &bundleName,
                                                           const std::string &abilityName)
{
    if (tag.empty()) {
        return nullptr;
    }
    return AVSessionManagerImpl::GetInstance().CreateSession(tag, type, bundleName, abilityName);
}

std::shared_ptr<AVSession> AVSessionManager::GetSession()
{
    return nullptr;
}

std::vector<AVSessionDescriptor> AVSessionManager::GetAllSessionDescriptors()
{
    return {};
}

std::shared_ptr<AVSessionController> AVSessionManager::CreateController(int32_t sessionld)
{
    return nullptr;
}

std::shared_ptr<AVSessionController> AVSessionManager::GetController(int32_t sessionld)
{
    return nullptr;
}

std::vector<std::shared_ptr<AVSessionController>> AVSessionManager::GetAllControllers()
{
    return {};
}

int32_t AVSessionManager::RegisterSessionListener(std::shared_ptr<SessionListener> &listener)
{
    if (listener == nullptr) {
        return ERR_INVALID_PARAM;
    }
    return AVSessionManagerImpl::GetInstance().RegisterSessionListener(listener);
}

int32_t AVSessionManager::RegisterServiceDeathCallback(const DeathCallback &callback)
{
    return AVSessionManagerImpl::GetInstance().RegisterServiceDeathCallback(callback);
}

int32_t AVSessionManager::SendSystemMediaKeyEvent(MMI::KeyEvent &keyEvent)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionManager::SetSystemMediaVolume(int32_t volume)
{
    return AVSESSION_SUCCESS;
}
} // OHOS::AVSession