/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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


#include "softbus_session_manager_dynamic.h"

#include "malloc.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "migrate_avsession_constant.h"

namespace OHOS::AVSession {
#ifdef DSOFTBUS_ENABLE
    DynamicSocketCallbackFunc* callbackFunc_ = nullptr;
#endif

SoftbusSessionManagerDynamic& SoftbusSessionManagerDynamic::GetInstance()
{
    static SoftbusSessionManagerDynamic softbusSessionManagerDynamic;
    return softbusSessionManagerDynamic;
}

static SoftbusPeerSocketInfo ConvertSocketInfo(PeerSocketInfo info)
{
    SoftbusPeerSocketInfo socketInfo;
    socketInfo.name = info.name;
    socketInfo.networkId = info.networkId;
    socketInfo.pkgName = info.pkgName;
    socketInfo.dataType = static_cast<SoftbusTransDataType>(info.dataType);
    socketInfo.accountId = info.accountId;
    socketInfo.extraData = info.extraData;
    socketInfo.dataLen = info.dataLen;
    return socketInfo;
}

#ifdef DSOFTBUS_ENABLE
static void OnBind(int32_t socket, PeerSocketInfo info)
{
    SLOGI("SoftbusClient OnBind socket[%{public}d]", socket);
    if (callbackFunc_ != nullptr) {
        SoftbusPeerSocketInfo socketInfo = ConvertSocketInfo(info);
        callbackFunc_->OnBind(socket, socketInfo);
    }
}

static void OnShutdown(int32_t socket, ShutdownReason reason)
{
    SLOGI("SoftbusClient OnSessionClosed sessionId[%{public}d], reason[%{public}d]", socket, reason);
    if (callbackFunc_ != nullptr) {
        callbackFunc_->OnShutdown(socket, static_cast<SoftbusShutdownReason>(reason));
    }
}

static void OnBytes(int socket, const void *data, unsigned int dataLen)
{
    SLOGI("SoftbusClient OnBytesReceived sessionId[%{public}d], datalen[%{public}d]", socket, dataLen);
    if (callbackFunc_ != nullptr) {
        callbackFunc_->OnBytes(socket, data, dataLen);
    }
}

static void OnMessage(int socket, const void *data, unsigned int dataLen)
{
    SLOGI("SoftbusClient OnMessageReceived sessionId[%{public}d], datalen[%{public}d]", socket, dataLen);
    if (callbackFunc_ != nullptr) {
        callbackFunc_->OnMessage(socket, data, dataLen);
    }
}

static ISocketListener iSessionListener = {
    .OnBind = OnBind,
    .OnShutdown = OnShutdown,
    .OnBytes = OnBytes,
    .OnMessage = OnMessage
};

int32_t SoftbusSessionManagerDynamic::Socket(const std::string &pkgName)
{
    if (pkgName.c_str() == nullptr) {
        SLOGE("pkg name is null");
        return AVSESSION_ERROR;
    }
    SocketInfo info = {
        .name = const_cast<char *>(CONFIG_SOFTBUS_SESSION_TAG),
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .dataType = TransDataType::DATA_TYPE_BYTES
    };
    int32_t socket = ::Socket(info);
    QosTV serverQos[] = {
        {.qos = QOS_TYPE_MIN_BW,        .value = 64 * 1024 }, //最小带宽64k
        {.qos = QOS_TYPE_MAX_LATENCY,   .value = 19000 }, //最大建链时延19s
        {.qos = QOS_TYPE_MIN_LATENCY,   .value = 500 }, //最小建链时延0.5s
    };
    int32_t ret = ::Listen(socket, serverQos, qosCount, &iSessionListener);
    if (ret == 0) {
        SLOGI("service success ,socket[%{public}d]", socket);
        //建立服务成功
    } else {
        SLOGI("service failed ,ret[%{public}d]", ret);
        //建立服务失败，错误码
    }
    return socket;
}

int32_t SoftbusSessionManagerDynamic::Bind(const std::string &peerNetworkId, const std::string &pkgName)
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
        .dataType = TransDataType::DATA_TYPE_BYTES
    };
    int32_t socket = ::Socket(info);
    QosTV serverQos[] = {
        {.qos = QOS_TYPE_MIN_BW,        .value = 64 * 1024 }, //最小带宽64k
        {.qos = QOS_TYPE_MAX_LATENCY,   .value = 19000 }, //最大建链时延19s
        {.qos = QOS_TYPE_MIN_LATENCY,   .value = 500 }, //最小建链时延0.5s
    };
    int32_t ret = ::Bind(socket, serverQos, qosCount, &iSessionListener);
    if (ret == 0) {
        SLOGI("service success ,socket[%{public}d]", socket);
        //建立服务成功
        return socket;
    } else {
        SLOGI("service failed ,ret[%{public}d]", ret);
        //建立服务失败，错误码
        return AVSESSION_ERROR;
    }
}

void SoftbusSessionManagerDynamic::Shutdown(int32_t socket)
{
    SLOGI("SoftbusClient socket Shutdown with mallopt");
    ::Shutdown(socket);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
}

int32_t SoftbusSessionManagerDynamic::SendMessage(int32_t socket, const std::string &data)
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

int32_t SoftbusSessionManagerDynamic::SendBytes(int32_t socket, const std::string &data)
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

void SoftbusSessionManagerDynamic::RegisterSocketCallback(DynamicSocketCallbackFunc* callbackFunc)
{
    SLOGI("SoftbusClient RegisterSocketCallback");
    callbackFunc_ = callbackFunc;
}

extern "C" int32_t DSocket(const std::string &pkgName)
{
    return SoftbusSessionManagerDynamic::GetInstance().Socket(pkgName);
}

extern "C" int32_t DBind(const std::string &peerNetworkId, const std::string &pkgName)
{
    return SoftbusSessionManagerDynamic::GetInstance().Bind(peerNetworkId, pkgName);
}

extern "C" void DShutdown(int32_t socket)
{
    SoftbusSessionManagerDynamic::GetInstance().Shutdown(socket);
}

extern "C" int32_t DSendMessage(int32_t socket, const std::string &data)
{
    return SoftbusSessionManagerDynamic::GetInstance().SendMessage(socket, data);
}

extern "C" int32_t DSendBytes(int32_t socket, const std::string &data)
{
    return SoftbusSessionManagerDynamic::GetInstance().SendBytes(socket, data);
}

extern "C" void DRegisterSocketCallback(DynamicSocketCallbackFunc* callbackFunc)
{
    SoftbusSessionManagerDynamic::GetInstance().RegisterSocketCallback(callbackFunc);
}
#endif
} // namespace OHOS::AVSession
