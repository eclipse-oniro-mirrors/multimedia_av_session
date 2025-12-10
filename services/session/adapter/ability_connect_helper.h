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

#define AVSESSION_START_CALL_ABILITY_CODE 1032
#define AVSESSION_CONNECT_ABILITY_WITH_TYPE 1034
#define AVSESSION_DISCONNECT_ABILITY 1003
#define AVSESSION_EXTENSION_ABILITY_TYPE_SERVICE 3

namespace OHOS::AVSession {
class AbilityConnectHelper {
public:
    static AbilityConnectHelper& GetInstance();

    int32_t StartAbilityForegroundByCall(const std::string& bundleName, const std::string& abilityName);

    int32_t StartAbilityByCall(const std::string &bundleName, const std::string &abilityName);

private:
   sptr<IRemoteObject> GetSystemAbility();

   const std::u16string ABILITY_MANAGER_INTERFACE_TOKEN = u"ohos.aafwk.AbilityManager";
};

class ExtensionConnectHelper {
public:
    static ExtensionConnectHelper& GetInstance();

    int32_t StartDesktopLyricAbility(const std::string &sessionId, int32_t userId, std::function<void(int32_t)> cb);

    int32_t StopDesktopLyricAbility();

private:
    int32_t ConnectAbilityCommon(const AAFwk::Want &want, sptr<IRemoteObject> connect, int32_t userId);

    int32_t DisconnectAbility(const sptr<IRemoteObject> &connect);

    sptr<IRemoteObject> GetSystemAbility();

    const std::u16string EXTENSION_MANAGER_INTERFACE_TOKEN = u"ohos.aafwk.ExtensionManager";
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

class DesktopLyricCallConnection : public AbilityConnectionStub {
public:
    explicit DesktopLyricCallConnection(std::function<void(int32_t)> cb)
        : callback_(std::move(cb)) {};
    ~DesktopLyricCallConnection() override;

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;

private:
    std::function<void(int32_t)> callback_;
};
} // namespace OHOS::AVSession
#endif /* ABILITY_CONNECT_HELPER_H */