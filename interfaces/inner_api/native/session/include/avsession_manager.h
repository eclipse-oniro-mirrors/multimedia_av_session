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

#ifndef OHOS_AVSESSION_MANAGER_H
#define OHOS_AVSESSION_MANAGER_H

#include <functional>
#include <string>
#include <memory>

#include "av_session.h"
#include "avsession_controller.h"
#include "avsession_info.h"
#include "key_event.h"

namespace OHOS::AVSession {
class AVSessionManager {
public:
    static AVSessionManager& GetInstance();

    virtual std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                                     const AppExecFwk::ElementName& elementName) = 0;

    virtual std::vector<AVSessionDescriptor> GetAllSessionDescriptors() = 0;

    virtual std::vector<AVSessionDescriptor> GetActivatedSessionDescriptors() = 0;

    virtual int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) = 0;

    virtual std::shared_ptr<AVSessionController> CreateController(const std::string& sessionId) = 0;

    virtual int32_t RegisterSessionListener(const std::shared_ptr<SessionListener>& listener) = 0;

    virtual int32_t RegisterServiceDeathCallback(const DeathCallback& callback) = 0;

    virtual int32_t UnregisterServiceDeathCallback() = 0;

    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    virtual int32_t SendSystemControlCommand(const AVControlCommand& command) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_H