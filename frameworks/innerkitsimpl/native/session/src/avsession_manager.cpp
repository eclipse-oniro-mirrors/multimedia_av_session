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
std::shared_ptr<AVSession> AVSessionManager::CreateSession(const std::string &tag)
{
    if (tag.empty()) {
        return nullptr;
    }
    return AVSessionManagerImpl::GetInstance().CreateSession(tag);
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
} // OHOS::AVSession