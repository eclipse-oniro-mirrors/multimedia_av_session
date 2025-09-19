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
SoftbusSessionManager& SoftbusSessionManager::GetInstance()
{
    static SoftbusSessionManager softbusSessionListener;
    return softbusSessionListener;
}

static void OnBind(int32_t socket, PeerSocketInfo info)
{
    SLOGI("OnBind sessionId[%{public}d] result[%{public}s]", socket,
        SoftbusSessionUtils::AnonymizeDeviceId(std::string(info.networkId ? info.networkId : "")).c_str());
    SoftbusSessionManager::GetInstance().OnBind(socket, info);
}

static void OnShutdown(int32_t socket, ShutdownReason reason)
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

static ISocketListener iSessionListener = {
    .OnBind = OnBind,
    .OnShutdown = OnShutdown,
    .OnBytes = OnBytes,
    .OnMessage = OnMessage
};

int32_t SoftbusSessionManager::Socket(const std::string &pkgName)
{
    if (pkgName.c_str() == nullptr) {
        SLOGE("pkg name is null");
        return AVSESSION_ERROR;
    }
    SocketInfo info = {
        .name = const_cast<char *>(CONFIG_SOFTBUS_SESSION_TAG),
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socket = ::Socket(info);
    QosTV serverQos[] = {
        {.qos = QOS_TYPE_MIN_BW,        .value = 64 * 1024 }, //最小带宽64k
        {.qos = QOS_TYPE_MAX_LATENCY,   .value = 19000 }, //最大建链时延19s
        {.qos = QOS_TYPE_MIN_LATENCY,   .value = 500 }, //最小建链时延0.5s
    };
    int32_t ret = ::Listen(socket, serverQos, QOS_COUNT, &iSessionListener);
    if (ret == 0) {
        SLOGI("service success ,socket[%{public}d]", socket);
        //建立服务成功
    } else {
        SLOGI("service failed ,ret[%{public}d]", ret);
        //建立服务失败，错误码
    }
    return socket;
}

int32_t SoftbusSessionManager::Bind(const std::string &peerNetworkId, const std::string &pkgName)
{
    if (peerNetworkId.c_str() == nullptr || peerNetworkId.length() <= 0 || pkgName.c_str() == nullptr) {
        SLOGE("pkg or networkId name is empty");
        return AVSESSION_ERROR;
    }
    SocketInfo info = {
        .name = const_cast<char *>(CONFIG_SOFTBUS_SESSION_TAG),
        .peerName = const_cast<char *>(CONFIG_SOFTBUS_SESSION_TAG),
        .peerNetworkId = const_cast<char *>(peerNetworkId.c_str()),
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socket = ::Socket(info);
    QosTV serverQos[] = {
        {.qos = QOS_TYPE_MIN_BW,        .value = 64 * 1024 }, //最小带宽64k
        {.qos = QOS_TYPE_MAX_LATENCY,   .value = 19000 }, //最大建链时延19s
        {.qos = QOS_TYPE_MIN_LATENCY,   .value = 500 }, //最小建链时延0.5s
    };
    int32_t ret = ::Bind(socket, serverQos, QOS_COUNT, &iSessionListener);
    if (ret == 0) {
        SLOGI("service success ,socket[%{public}d]", socket);
        std::lock_guard lockGuard(socketLock_);
        mMap_.insert({socket, peerNetworkId});
        //建立服务成功
        return socket;
    } else {
        SLOGI("service failed ,ret[%{public}d]", ret);
        //建立服务失败，错误码
        return AVSESSION_ERROR;
    }
}

void SoftbusSessionManager::Shutdown(int32_t socket)
{
    SLOGI("socket Shutdown with mallopt");
    ::Shutdown(socket);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
}

int32_t SoftbusSessionManager::SendMessage(int32_t socket, const std::string &data)
{
    if (socket <= 0 || data == "") {
        SLOGE("the params invalid, unable to send message by session.");
        return AVSESSION_ERROR;
    }
    int ret = ::SendMessage(socket, data.c_str(), data.length());
    if (ret != 0) {
        SLOGE("SendMessage error, ret = %{public}d", ret);
        return AVSESSION_ERROR;
    }
    return ret;
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
    int ret = ::SendBytes(socket, data.c_str(), data.length());
    if (ret != 0) {
        SLOGE("SendBytes error, ret = %{public}d", ret);
        return AVSESSION_ERROR;
    }
    return ret;
}

int32_t SoftbusSessionManager::SendBytesForNext(int32_t socket, const std::string &data)
{
    if (socket <= 0 || data == "") {
        SLOGE("the params invalid, unable to send sendBytes by session.");
        return AVSESSION_ERROR;
    }
    int ret = ::SendBytes(socket, data.c_str(), data.length());
    if (ret != 0) {
        SLOGE("SendBytes error, ret = %{public}d", ret);
        return AVSESSION_ERROR;
    }
    return ret;
}

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

void SoftbusSessionManager::OnBind(int32_t socket, PeerSocketInfo info)
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

void SoftbusSessionManager::OnShutdown(int32_t socket, ShutdownReason reason)
{
    SLOGI("ShutdownReason = %{public}d", reason);
    std::lock_guard lockGuard(socketLock_);
    for (auto listener : sessionListeners_) {
        listener->OnShutdown(socket, reason);
        mMap_.erase(socket);
    }
}

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
