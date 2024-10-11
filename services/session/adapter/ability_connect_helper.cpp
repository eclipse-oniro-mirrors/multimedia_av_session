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

#include "ability_manager_interface.h"
#include "ability_manager_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {
AbilityConnectHelper& AbilityConnectHelper::GetInstance()
{
    static AbilityConnectHelper abilityConnectHelper;
    return abilityConnectHelper;
}

int32_t AbilityConnectHelper::StartAbilityForegroundByCall(const std::string& bundleName,
    const std::string& abilityName)
{
    SLOGI("StartAbilityForegroundByCall bundleName=%{public}s abilityName=%{public}s",
        bundleName.c_str(), abilityName.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ABILITY_MANAGER_INTERFACE_TOKEN)) {
        SLOGE("write interface token failed");
        return ERR_MARSHALLING;
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    want.SetParam("ohos.aafwk.param.callAbilityToForeground", true);

    if (!data.WriteParcelable(&want)) {
        SLOGE("want write failed");
        return ERR_INVALID_PARAM;
    }
    sptr<AAFwk::IAbilityConnection> connect = new(std::nothrow) AbilityConnectCallback();
    if (connect == nullptr) {
        SLOGE("connect is nullptr");
        return ERR_NO_MEMORY;
    }
    if (!data.WriteRemoteObject(connect->AsObject())) {
        SLOGE("resolve write failed");
        return ERR_MARSHALLING;
    }
    if (!data.WriteBool(false)) {
        SLOGE("Failed to write flag");
        return ERR_MARSHALLING;
    }
    if (!data.WriteInt32(-1)) { // -1 is default connect id of ability manager
        SLOGE("Failed to write connect id");
        return ERR_MARSHALLING;
    }

    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    if (remote->SendRequest(static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_CALL_ABILITY),
        data, reply, option) != 0) {
        SLOGE("Send request error");
        return ERR_IPC_SEND_REQUEST;
    }
    return reply.ReadInt32() == ERR_OK ? AVSESSION_SUCCESS : ERR_ABILITY_NOT_AVAILABLE;
}

int32_t AbilityConnectHelper::StartAbilityByCall(const std::string& bundleName, const std::string& abilityName)
{
    SLOGI("bundleName=%{public}s abilityName=%{public}s", bundleName.c_str(), abilityName.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ABILITY_MANAGER_INTERFACE_TOKEN)) {
        SLOGE("write interface token failed");
        return ERR_MARSHALLING;
    }

    AAFwk::Want want;
    AppExecFwk::ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    if (!data.WriteParcelable(&want)) {
        SLOGE("want write failed");
        return ERR_INVALID_PARAM;
    }

    sptr<AAFwk::IAbilityConnection> connect = new(std::nothrow) AbilityConnectCallback();
    if (connect == nullptr) {
        SLOGE("connect is nullptr");
        return ERR_NO_MEMORY;
    }
    if (!data.WriteRemoteObject(connect->AsObject())) {
        SLOGE("resolve write failed");
        return ERR_MARSHALLING;
    }
    if (!data.WriteBool(false)) {
        SLOGE("Failed to write flag");
        return ERR_MARSHALLING;
    }
    if (!data.WriteInt32(-1)) { // -1 is default connect id of ability manager
        SLOGE("Failed to write connect id");
        return ERR_MARSHALLING;
    }

    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    if (remote->SendRequest(static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_CALL_ABILITY),
        data, reply, option) != 0) {
        SLOGE("Send request error");
        return ERR_IPC_SEND_REQUEST;
    }
    return reply.ReadInt32() == ERR_OK ? AVSESSION_SUCCESS : ERR_ABILITY_NOT_AVAILABLE;
}

sptr<IRemoteObject> AbilityConnectHelper::GetSystemAbility()
{
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        SLOGE("Fail to get registry");
        return nullptr;
    }
    sptr<IRemoteObject> remote = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remote == nullptr) {
        SLOGE("Fail to connect ability manager service");
        return nullptr;
    }
    SLOGI("Connect ability manager service success");
    return remote;
}

AbilityConnectionStub::AbilityConnectionStub()
{}

AbilityConnectionStub::~AbilityConnectionStub()
{}

int AbilityConnectionStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    auto descriptor = AbilityConnectionStub::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        SLOGE("Local descriptor is not equal to remote");
        return AVSESSION_ERROR;
    }

    auto element = data.ReadParcelable<AppExecFwk::ElementName>();
    if (element == nullptr) {
        SLOGE("callback stub receive element is nullptr");
        return AVSESSION_ERROR;
    }
    if (code == AAFwk::IAbilityConnection::ON_ABILITY_CONNECT_DONE) {
        auto remoteObject = data.ReadRemoteObject();
        if (remoteObject == nullptr) {
            SLOGE("callback stub receive remoteObject is nullptr");
            delete element;
            element = nullptr;
            return AVSESSION_ERROR;
        }
        auto resultCode = data.ReadInt32();
        OnAbilityConnectDone(*element, remoteObject, resultCode);
        delete element;
        element = nullptr;
        return ERR_NONE;
    }
    if (code == AAFwk::IAbilityConnection::ON_ABILITY_DISCONNECT_DONE) {
        auto resultCode = data.ReadInt32();
        OnAbilityDisconnectDone(*element, resultCode);
        delete element;
        element = nullptr;
        return ERR_NONE;
    }
    delete element;
    element = nullptr;
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

AbilityConnectCallback::~AbilityConnectCallback()
{}

void AbilityConnectCallback::OnAbilityConnectDone(const AppExecFwk::ElementName& element,
    const sptr<IRemoteObject>& __attribute__((unused)) remoteObject, int resultCode)
{
    SLOGI("OnAbilityConnectDone callback, retcode:%{public}d, bundlename:%{public}s, abilityname:%{public}s",
        resultCode, element.GetBundleName().c_str(), element.GetAbilityName().c_str());
}

void AbilityConnectCallback::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    SLOGI("OnAbilityDisConnectDone callback, retcode:%{public}d, bundlename:%{public}s, abilityname:%{public}s",
        resultCode, element.GetBundleName().c_str(), element.GetAbilityName().c_str());
}
} // namespace OHOS::AVSession