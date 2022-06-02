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
#include "avsession_log.h"

namespace OHOS::AVSession {
std::shared_ptr<AVSession> AVSessionManager::CreateSession(const std::string &tag, int32_t type,
                                                           const std::string &bundleName,
                                                           const std::string &abilityName)
{
    if (tag.empty() || bundleName.empty() || abilityName.empty()) {
        SLOGE("param is invalid");
        return nullptr;
    }
    if (type != AVSession::SESSION_TYPE_AUDIO && type != AVSession::SESSION_TYPE_VIDEO) {
        SLOGE("type is invalid");
        return nullptr;
    }
    return AVSessionManagerImpl::GetInstance().CreateSession(tag, type, bundleName, abilityName);
}

std::vector<AVSessionDescriptor> AVSessionManager::GetAllSessionDescriptors()
{
    return AVSessionManagerImpl::GetInstance().GetAllSessionDescriptors();
}

std::shared_ptr<AVSessionController> AVSessionManager::CreateController(int32_t sessionId)
{
    if (sessionId < 0) {
        SLOGE("sessionId is invalid");
        return nullptr;
    }
    return AVSessionManagerImpl::GetInstance().CreateController(sessionId);
}

int32_t AVSessionManager::RegisterSessionListener(const std::shared_ptr<SessionListener> &listener)
{
    if (listener == nullptr) {
        SLOGE("listener is nullptr");
        return ERR_INVALID_PARAM;
    }
    return AVSessionManagerImpl::GetInstance().RegisterSessionListener(listener);
}

int32_t AVSessionManager::RegisterServiceDeathCallback(const DeathCallback &callback)
{
    return AVSessionManagerImpl::GetInstance().RegisterServiceDeathCallback(callback);
}

int32_t AVSessionManager::UnregisterServiceDeathCallback()
{
    return AVSessionManagerImpl::GetInstance().UnregisterServiceDeathCallback();
}

int32_t AVSessionManager::SendSystemMediaKeyEvent(const MMI::KeyEvent &keyEvent)
{
    if (!keyEvent.IsValid()) {
        SLOGE("keyEvent is invalid");
        return ERR_INVALID_PARAM;
    }
    return AVSessionManagerImpl::GetInstance().SendSystemMediaKeyEvent(keyEvent);
}

int32_t AVSessionManager::SendSystemControlCommand(const AVControlCommand &command)
{
    if (!command.IsValid()) {
        SLOGE("command is invalid");
        return ERR_INVALID_PARAM;
    }
    return AVSessionManagerImpl::GetInstance().SendSystemControlCommand(command);
}
} // OHOS::AVSession