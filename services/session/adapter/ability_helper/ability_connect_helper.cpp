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

#include "ability_connect_helper.h"

#include "ability_manager_client.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
void AbilityConnectHelper::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &__attribute__((unused)) remoteObject, int resultCode)
{
    SLOGI("OnAbilityConnectDone callback, retcode:%{public}d, bundlename:%{public}s, abilityname:%{public}s",
        resultCode, element.GetBundleName().c_str(), element.GetAbilityName().c_str());
}

void AbilityConnectHelper::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    SLOGI("OnAbilityDisConnectDone callback, retcode:%{public}d, bundlename:%{public}s, abilityname:%{public}s",
        resultCode, element.GetBundleName().c_str(), element.GetAbilityName().c_str());
}
} // namespace OHOS::AVSession

int32_t StartAbilityByCall(const std::string bundleName, const std::string abilityName)
{
    SLOGI("bundleName=%{public}s abilityName=%{public}s", bundleName.c_str(), abilityName.c_str());
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    OHOS::sptr<OHOS::AAFwk::IAbilityConnection> connect = new(std::nothrow) OHOS::AVSession::AbilityConnectHelper();
    return OHOS::AAFwk::AbilityManagerClient::GetInstance()->StartAbilityByCall(want, connect, nullptr);
}