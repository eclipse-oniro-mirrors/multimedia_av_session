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
    static std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                                    const std::string& bundleName, const std::string& abilityName);

    static std::vector<AVSessionDescriptor> GetAllSessionDescriptors();

    static std::shared_ptr<AVSessionController> CreateController(int32_t sessionld);

    static int32_t RegisterSessionListener(std::shared_ptr<SessionListener>& listener);

    static int32_t RegisterServiceDeathCallback(const DeathCallback& callback);

    static int32_t UnregisterServiceDeathCallback();

    static int32_t SendSystemMediaKeyEvent(const MMI::KeyEvent& keyEvent);

    static int32_t SendSystemControlCommand(const AVControlCommand& command);
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_H