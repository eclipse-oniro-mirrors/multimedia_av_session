/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CJ_AVSESSION_MANAGER_IMPL_H
#define OHOS_CJ_AVSESSION_MANAGER_IMPL_H

#include <map>
#include <string>

#include "singleton.h"
#include "ability.h"
#include "ability_context.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {

class CJAVSessionManagerImpl {
    DECLARE_DELAYED_SINGLETON(CJAVSessionManagerImpl);
public:
    DISALLOW_COPY_AND_MOVE(CJAVSessionManagerImpl);
    int32_t CreateAVSession(OHOS::AbilityRuntime::AbilityContext& context,
                            const std::string& tag, int32_t& type, int64_t& session, char*& sessionId);
    int32_t CreateController(const std::string& sessionId);
};

#define CJ_AVSESSION_MANAGER_IMPL OHOS::DelayedSingleton<OHOS::AVSession::CJAVSessionManagerImpl>::GetInstance()

} // namespace AVSession::OHOS
#endif // OHOS_CJ_AVSESSION_MANAGER_IMPL_H