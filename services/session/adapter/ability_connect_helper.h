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

#ifndef ABILITY_CONNECT_HELPER_H
#define ABILITY_CONNECT_HELPER_H

#include <string>

#include "ability_connect_callback_interface.h"
#include "ability_connect_callback_stub.h"
#include "element_name.h"
#include "iremote_stub.h"
#include "want.h"
#include "insight_intent_execute_param.h"

namespace OHOS::AVSession {
class AbilityConnectHelper {
public:
    static AbilityConnectHelper& GetInstance();

    int32_t StartAbilityForegroundByCall(const std::string& bundleName, const std::string& abilityName);

    int32_t StartAbilityByCall(const std::string &bundleName, const std::string &abilityName);
    
    int32_t StartMediaIntent(AppExecFwk::InsightIntentExecuteParam &executeParam);

private:
   sptr<IRemoteObject> GetSystemAbility();

   const std::u16string ABILITY_MANAGER_INTERFACE_TOKEN = u"ohos.aafwk.AbilityManager";
};

class AbilityConnectionStub : public IRemoteStub<AAFwk::IAbilityConnection> {
public:
    AbilityConnectionStub();
    virtual ~AbilityConnectionStub();

    int OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    DISALLOW_COPY_AND_MOVE(AbilityConnectionStub);
};

class AbilityConnectCallback : public AbilityConnectionStub {
public:
    AbilityConnectCallback() {};
    ~AbilityConnectCallback() override;

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;
};
} // namespace OHOS::AVSession
#endif /* ABILITY_CONNECT_HELPER_H */