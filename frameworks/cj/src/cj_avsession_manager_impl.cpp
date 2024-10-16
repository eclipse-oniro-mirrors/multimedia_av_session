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

#include "cj_avsession_controller_impl.h"

#include "av_session.h"
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "cj_avsession_impl.h"
#include "cj_avsession_utils.h"

namespace OHOS::AVSession {

CJAVSessionManagerImpl::CJAVSessionManagerImpl() {}

CJAVSessionManagerImpl::~CJAVSessionManagerImpl() {}

int32_t CJAVSessionManagerImpl::CreateAVSession(OHOS::AbilityRuntime::AbilityContext& context,
    const std::string& tag, int32_t& type, int64_t& session, char*& sessionId)
{
    auto abilityInfo = context.GetAbilityInfo();
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(abilityInfo->bundleName);
    elementName.SetAbilityName(abilityInfo->name);
    std::shared_ptr<OHOS::AVSession::AVSession> out;
    int32_t ret = AVSessionManager::GetInstance().CreateSession(tag, type, elementName, out);
    if (ret == AVSESSION_SUCCESS) {
        auto sid = out->GetSessionId();
        convertNativeToCJStruct(sid, sessionId);
        session = CJAVSessionImpl(out).GetID();
    }
    return ret;
}

int32_t CJAVSessionManagerImpl::CreateController(const std::string &sessionId)
{
    std::shared_ptr<AVSessionController> nativeController;
    int32_t errCode = AVSessionManager::GetInstance().CreateController(sessionId, nativeController);
    if (errCode != AVSESSION_SUCCESS) {
        return errCode;
    }
    auto controller = CJAVSessionControllerImpl::NewInstance(nativeController);
    if (controller) {
        return errCode;
    } else {
        return ERR_NO_MEMORY;
    }
}

} // namespace AVSession::OHOS