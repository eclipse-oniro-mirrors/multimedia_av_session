/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_session_manager.h"

#include "avsession_log.h"
#include "avsession_errors.h"
#include "migrate_avsession_constant.h"
#include "audio_device_manager.h"
#include "softbus_session_utils.h"

namespace OHOS::AVSession {

static const std::string SOFTBUS_DYNAMIC_LIBRARY_PATH = std::string("libsoftbus_manager_dynamic.z.so");

SoftbusSessionManager& SoftbusSessionManager::GetInstance()
{
    static SoftbusSessionManager softbusSessionListener;
    return softbusSessionListener;
}

#ifdef DSOFTBUS_ENABLE
static void OnBind(int32_t socket, SoftbusPeerSocketInfo info)
{
    SLOGI("OnBind sessionId[%{public}d] result[%{public}s]", socket,
        SoftbusSessionUtils::AnonymizeDeviceId(std::string(info.networkId ? info.networkId : "")).c_str());
    SoftbusSessionManager::GetInstance().OnBind(socket, info);
}

static void OnShutdown(int32_t socket, SoftbusShutdownReason reason)
{
    SLOGI("OnSessionClosed sessionId[%{public}d], reason[%{public}d]", socket, reason);
    SoftbusSessionManager::GetInstance().OnShutdown(socket, reason);
}

static void OnBytes(int socket, const void *data, unsigned int dataLen)
{
    SLOGI("OnBytesReceived sessionId[%{public}d], datalen[%{public}d]", socket, dataLen);
    std::string msg = std::string(static_cast<const char*>(data), dataLen);
    SoftbusSessionManager::GetInstance().OnBytes(socket, msg.c_str(), dataLen);
}

static void OnMessage(int socket, const void *data, unsigned int dataLen)
{
    SLOGI("OnMessageReceived sessionId[%{public}d], datalen[%{public}d]", socket, dataLen);
    std::string msg = std::string(static_cast<const char*>(data), dataLen);
    SoftbusSessionManager::GetInstance().OnMessage(socket, msg.c_str(), dataLen);
}

static DynamicSocketCallbackFunc callbackFunc = {
    .OnBind = OnBind,
    .OnShutdown = OnShutdown,
    .OnBytes = OnBytes,
    .OnMessage = OnMessage
};

int32_t SoftbusSessionManager::Socket(const std::string &pkgName)
{
    using SocketCallbackFunc = void(*)(DynamicSocketCallbackFunc*);
    SocketCallbackFunc registerCallback = reinterpret_cast<SocketCallbackFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DRegisterSocketCallback"));
    if (registerCallback) {
        SLOGI("DRegisterSocketCallback");
        registerCallback(&callbackFunc);
    }

    using SocketFunc = int32_t(*)(const std::string&);
    SocketFunc socket = reinterpret_cast<SocketFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DSocket"));
    if (socket) {
        SLOGI("DSocket");
        return socket(pkgName);
    }
    SLOGE("dlopen DSocket fail");
    return AVSESSION_ERROR;
}

int32_t SoftbusSessionManager::Bind(const std::string &peerNetworkId, const std::string &pkgName)
{
    if (peerNetworkId.c_str() == nullptr || peerNetworkId.length() <= 0 || pkgName.c_str() == nullptr) {
        SLOGE("pkg or networkId name is empty");
        return AVSESSION_ERROR;
    }

    using BindFunc = int32_t(*)(const std::string&, const std::string&);
    BindFunc bind = reinterpret_cast<BindFunc>(dynamicLoader->GetFuntion(SOFTBUS_DYNAMIC_LIBRARY_PATH, "DBind"));
    if (bind) {
        SLOGI("DBind");
        int32_t socket = bind(peerNetworkId, pkgName);
        if (socket != -1) {
            SLOGI("DBind success ,socket[%{public}d]", socket);
            std::lock_guard lockGuard(socketLock_);
            mMap_.insert({socket, peerNetworkId});
            return socket;
        } else {
            SLOGE("DBind failed");
            return AVSESSION_ERROR;
        }
    }
    SLOGE("dlopen DBind fail");
    return AVSESSION_ERROR;
}

void SoftbusSessionManager::Shutdown(int32_t socket)
{
    SLOGI("socket Shutdown with mallopt");
    using ShutdownFunc = void(*)(int32_t);
    ShutdownFunc shutdown = reinterpret_cast<ShutdownFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DShutdown"));
    if (shutdown) {
        SLOGI("DShutdown");
        shutdown(socket);
    } else {
        SLOGE("dlopen DShutdown fail");
    }
}

int32_t SoftbusSessionManager::SendMessage(int32_t socket, const std::string &data)
{
    if (socket <= 0 || data == "") {
        SLOGE("the params invalid, unable to send message by session.");
        return AVSESSION_ERROR;
    }
    using SendMessageFunc = int32_t(*)(int32_t, const std::string&);
    SendMessageFunc sendMsg = reinterpret_cast<SendMessageFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DSendMessage"));
    if (sendMsg) {
        return sendMsg(socket, data);
    }
    SLOGE("dlopen DSendMessage fali");
    return AVSESSION_ERROR;
}

int32_t SoftbusSessionManager::SendBytes(int32_t socket, const std::string &data)
{
    if (AudioDeviceManager::GetInstance().GetSessionInfoSyncState()) {
        SLOGE("car a2dp online, dont send.");
        return AVSESSION_ERROR;
    }
    if (socket <= 0 || data == "") {
        SLOGE("the params invalid, unable to send sendBytes by session.");
        return AVSESSION_ERROR;
    }
    using SendBytesFunc = int32_t(*)(int32_t, const std::string&);
    SendBytesFunc sendBytes = reinterpret_cast<SendBytesFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DSendBytes"));
    if (sendBytes) {
        return sendBytes(socket, data);
    }
    SLOGE("SendBytes dlopen DSendBytes fali");
    return AVSESSION_ERROR;
}

int32_t SoftbusSessionManager::SendBytesForNext(int32_t socket, const std::string &data)
{
    if (socket <= 0 || data == "") {
        SLOGE("the params invalid, unable to send sendBytes by session.");
        return AVSESSION_ERROR;
    }
    using SendBytesFunc = int32_t(*)(int32_t, const std::string&);
    SendBytesFunc sendBytes = reinterpret_cast<SendBytesFunc>(dynamicLoader->GetFuntion(
        SOFTBUS_DYNAMIC_LIBRARY_PATH, "DSendBytes"));
    if (sendBytes) {
        return sendBytes(socket, data);
    }
    SLOGE("SendBytesForNext dlopen DSendBytes fali");
    return AVSESSION_ERROR;
}
#endif

int32_t SoftbusSessionManager::ObtainPeerDeviceId(int32_t socket, std::string &deviceId)
{
    CHECK_AND_RETURN_RET_LOG(
        socket > 0, AVSESSION_ERROR, "the session is null, unable to obtain the peer device id.");
    if (mMap_.find(socket) == mMap_.end()) {
        SLOGE("no find deviceid.");
        return AVSESSION_ERROR;
    } else {
        deviceId = mMap_[socket];
        return AVSESSION_SUCCESS;
    }
}

void SoftbusSessionManager::AddSessionListener(std::shared_ptr<SoftbusSessionListener> softbusSessionListener)
{
    if (softbusSessionListener == nullptr) {
        SLOGE("the session listener is null, unable to add to session listener list.");
        return;
    }
    std::lock_guard lockGuard(socketLock_);
    sessionListeners_.clear();
    sessionListeners_.emplace_back(softbusSessionListener);
}

#ifdef DSOFTBUS_ENABLE
void SoftbusSessionManager::OnBind(int32_t socket, SoftbusPeerSocketInfo info)
{
    if (info.networkId == nullptr) {
        SLOGE("PeerSocketInfo is nullptr");
        return;
    }
    std::lock_guard lockGuard(socketLock_);
    for (auto listener : sessionListeners_) {
        listener->OnBind(socket, info);
        mMap_.insert({socket, info.networkId});
    }
}

void SoftbusSessionManager::OnShutdown(int32_t socket, SoftbusShutdownReason reason)
{
    SLOGI("ShutdownReason = %{public}d", reason);
    std::lock_guard lockGuard(socketLock_);
    for (auto listener : sessionListeners_) {
        listener->OnShutdown(socket, reason);
        mMap_.erase(socket);
    }
}
#endif

void SoftbusSessionManager::OnMessage(int32_t socket, const void *data, int32_t dataLen)
{
    if (data == nullptr) {
        SLOGE("message data is nullptr");
        return;
    }
    std::lock_guard lockGuard(socketLock_);
    for (auto listener : sessionListeners_) {
        listener->OnMessage(socket, data, dataLen);
    }
}

void SoftbusSessionManager::OnBytes(int32_t socket, const void *data, int32_t dataLen)
{
    if (data == nullptr) {
        SLOGE("bytes data is nullptr");
        return;
    }
    std::lock_guard lockGuard(socketLock_);
    for (auto listener : sessionListeners_) {
        listener->OnBytes(socket, data, dataLen);
    }
}
} // namespace OHOS::AVSession
