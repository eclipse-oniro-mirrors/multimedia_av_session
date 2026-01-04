/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "extension_connect_helper.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "system_ability_definition.h"
#include "avsession_pixel_map.h"
#include "avsession_utils.h"

namespace OHOS::AVSession {
const std::string MEDIA_CONTROL_BUNDLENAME = "com.ohos.mediacontroller";
const std::string DESKTOP_LYRIC_ABILITYNAME = "DesktopLyricAbility";
constexpr int32_t DESKTOP_LYRICS_ABILITY_CONNECTED = 2;
constexpr int32_t DESKTOP_LYRICS_ABILITY_DISCONNECTED = 4;
constexpr uint32_t OPEN = 1;

ExtensionConnectHelper &ExtensionConnectHelper::GetInstance()
{
    static ExtensionConnectHelper instance;
    return instance;
}

int32_t ExtensionConnectHelper::StartDesktopLyricAbility(const std::string &sessionId, const std::string &handler,
    int32_t userId, ConnectionStateChangedCallback cb, bool shouldBeRecreated)
{
    SLOGI("sessionId=%{public}s,handler=%{public}s,userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(sessionId).c_str(), handler.c_str(), userId);
    std::lock_guard<std::mutex> lock(desktopLyricConnMutex);
    auto item = desktopLyricConnectionMap_.find(userId);
    if (shouldBeRecreated || item == desktopLyricConnectionMap_.end() || item->second == nullptr) {
        desktopLyricConnectionMap_[userId] = new(std::nothrow) DesktopLyricCallConnection(cb, sessionId,
            handler, userId);
        CHECK_AND_RETURN_RET_LOG(desktopLyricConnectionMap_[userId] != nullptr, ERR_NO_MEMORY,
            "create desktop lyric connection fail");
    }

    AAFwk::Want want;
    want.SetElementName(MEDIA_CONTROL_BUNDLENAME, DESKTOP_LYRIC_ABILITYNAME);
    want.SetParam("sessionId", sessionId);
    int32_t result = ConnectAbilityCommon(want, desktopLyricConnectionMap_[userId], userId);
    CHECK_AND_RETURN_RET_LOG(result == ERR_NONE, AVSESSION_ERROR,
        "connect desktop lyric ability fail: %{public}d", result);
    return AVSESSION_SUCCESS;
}

int32_t ExtensionConnectHelper::StopDesktopLyricAbility(int32_t userId)
{
    std::lock_guard<std::mutex> lock(desktopLyricConnMutex);
    if (desktopLyricConnectionMap_.find(userId) == desktopLyricConnectionMap_.end()) {
        SLOGE("userId=%{public}d not found", userId);
        return AVSESSION_ERROR;
    }
    if (desktopLyricConnectionMap_[userId] == nullptr) {
        SLOGE("userId=%{public}d desktopLyricConnection is nullptr", userId);
        return AVSESSION_ERROR;
    }
    int32_t result = DisconnectAbility(desktopLyricConnectionMap_[userId]);
    CHECK_AND_RETURN_RET_LOG(result == ERR_NONE, AVSESSION_ERROR,
        "disconnect userId=%{public}d desktop lyric ability fail: %{public}d", userId, result);
    return AVSESSION_SUCCESS;
}

int32_t ExtensionConnectHelper::UploadDesktopLyricOperationInfo(const std::string &sessionId,
    const std::string &handler, uint32_t sceneCode, int32_t userId)
{
    std::lock_guard<std::mutex> lock(desktopLyricConnMutex);
    if (desktopLyricConnectionMap_.find(userId) == desktopLyricConnectionMap_.end()) {
        SLOGE("userId=%{public}d not found", userId);
        return AVSESSION_ERROR;
    }
    if (desktopLyricConnectionMap_[userId] == nullptr) {
        SLOGE("userId=%{public}d desktopLyricConnection is nullptr", userId);
        return AVSESSION_ERROR;
    }
    int32_t result = desktopLyricConnectionMap_[userId]->SendDesktopLyricOperationInfo(sessionId, handler, sceneCode);
    CHECK_AND_RETURN_RET_LOG(result == ERR_NONE, AVSESSION_ERROR,
        "upload userId=%{public}d desktop lyric operation info fail: %{public}d", userId, result);
    return AVSESSION_SUCCESS;
}

int32_t ExtensionConnectHelper::ConnectAbilityCommon(const AAFwk::Want &want, sptr<IRemoteObject> connect,
    int32_t userId)
{
    if (connect == nullptr) {
        SLOGE("null connect");
        return ERR_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(EXTENSION_MANAGER_INTERFACE_TOKEN)) {
        SLOGE("write interface token failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteParcelable(&want)) {
        SLOGE("want write failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteBool(true) || !data.WriteRemoteObject(connect)) {
        SLOGE("flag or connect write failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteBool(false)) {
        SLOGE("flag write failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteInt32(userId)) {
        SLOGE("userId write failed.");
        return ERR_MARSHALLING;
    }

    if (!data.WriteInt32(AVSESSION_EXTENSION_ABILITY_TYPE_SERVICE)) {
        SLOGE("extensionType write failed.");
        return ERR_MARSHALLING;
    }

    if (!data.WriteBool(false)) {
        SLOGE("isQueryExtensionOnly write failed");
        return ERR_MARSHALLING;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    int error = remote->SendRequest(AVSESSION_CONNECT_ABILITY_WITH_TYPE, data, reply, option);
    if (error != NO_ERROR) {
        SLOGE("Send request error: %{public}d", error);
        return ERR_IPC_SEND_REQUEST;
    }
    return reply.ReadInt32();
}

int32_t ExtensionConnectHelper::DisconnectAbility(const sptr<IRemoteObject> &connect)
{
    if (connect == nullptr) {
        SLOGE("null connect");
        return ERR_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(EXTENSION_MANAGER_INTERFACE_TOKEN)) {
        SLOGE("write interface token failed");
        return ERR_MARSHALLING;
    }
    if (!data.WriteRemoteObject(connect)) {
        SLOGE("connect write failed");
        return ERR_MARSHALLING;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        return ERR_SERVICE_NOT_EXIST;
    }
    auto error = remote->SendRequest(AVSESSION_DISCONNECT_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        SLOGE("Send request error: %{public}d", error);
        return ERR_IPC_SEND_REQUEST;
    }
    return reply.ReadInt32();
}

sptr<IRemoteObject> ExtensionConnectHelper::GetSystemAbility()
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

DesktopLyricCallConnection::~DesktopLyricCallConnection()
{}

void DesktopLyricCallConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    SLOGI("desktopLyric ability connect done");
    {
        std::lock_guard<std::mutex> lock(desktopLyricProxyMutex_);
        desktopLyricProxy_ = remoteObject;
    }
    if (callback_) {
        callback_(userId_, DESKTOP_LYRICS_ABILITY_CONNECTED);
    } else {
        SLOGE("callback no register");
    }
    SendDesktopLyricOperationInfo(sessionId_, handler_, OPEN);
}

void DesktopLyricCallConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    SLOGI("desktopLyric ability disconnect done");
    {
        std::lock_guard<std::mutex> lock(desktopLyricProxyMutex_);
        desktopLyricProxy_ = nullptr;
    }
    if (callback_) {
        callback_(userId_, DESKTOP_LYRICS_ABILITY_DISCONNECTED);
    } else {
        SLOGE("callback no register");
    }
}

int32_t DesktopLyricCallConnection::SendDesktopLyricOperationInfo(const std::string &sessionId,
    const std::string &handler, uint32_t sceneCode)
{
    SLOGI("sessionId:%{public}s, handler:%{public}s, sceneCode:%{public}d",
        AVSessionUtils::GetAnonySessionId(sessionId).c_str(), handler.c_str(), sceneCode);
    std::lock_guard<std::mutex> lock(desktopLyricProxyMutex_);
    CHECK_AND_RETURN_RET_LOG(desktopLyricProxy_ != nullptr, AVSESSION_ERROR,
        "desktopLyricProxy_ is nullptr");

    MessageParcel data;
    if (!data.WriteInterfaceToken(desktopLyricProxy_->GetInterfaceDescriptor())) {
        SLOGE("write interface token failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteString16(Str8ToStr16(sessionId))) {
        SLOGE("sessionId write failed");
        return ERR_MARSHALLING;
    }

    if (!data.WriteString16(Str8ToStr16(handler))) {
        SLOGE("handler write failed");
        return ERR_MARSHALLING;
    }

    MessageParcel reply;
    MessageOption option;
    int error = desktopLyricProxy_->SendRequest(static_cast<uint32_t>(sceneCode), data, reply, option);
    if (error != NO_ERROR) {
        SLOGE("Send request error: %{public}d", error);
        return ERR_IPC_SEND_REQUEST;
    }
    return reply.ReadInt32();
}
} // namespace OHOS::AVSession