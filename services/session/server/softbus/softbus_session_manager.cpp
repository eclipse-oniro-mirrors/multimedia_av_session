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
#include "session.h"
#include "migrate_avsession_constant.h"

namespace OHOS::AVSession {
SoftbusSessionManager& SoftbusSessionManager::GetInstance()
{
    static SoftbusSessionManager softbusSessionListener;
    return softbusSessionListener;
}

static int SessionOpened(int sessionId, int result)
{
    SLOGI("OnSessionOpend sessionId[%{public}d] result[%{public}d]", sessionId, result);
    return SoftbusSessionManager::GetInstance().OnSessionOpened(sessionId, result);
}

static void SessionClosed(int sessionId)
{
    SLOGI("OnSessionClosed sessionId[%{public}d]", sessionId);
    SoftbusSessionManager::GetInstance().OnSessionClosed(sessionId);
}

static void BytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    SLOGI("OnBytesReceived sessionId[%{public}d], datalen[%{public}d]", sessionId, dataLen);
    std::string msg = std::string(static_cast<const char*>(data), dataLen);
    SoftbusSessionManager::GetInstance().OnBytesReceived(sessionId, msg);
}

static void MessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    SLOGI("OnMessageReceived sessionId[%{public}d], datalen[%{public}d]", sessionId, dataLen);
    std::string msg = std::string(static_cast<const char*>(data), dataLen);
    SoftbusSessionManager::GetInstance().OnMessageReceived(sessionId, msg);
}

static ISessionListener iSessionListener = {
    .OnSessionOpened = SessionOpened,
    .OnSessionClosed = SessionClosed,
    .OnBytesReceived = BytesReceived,
    .OnMessageReceived = MessageReceived
};

SessionAttribute sessionAttr = {
    .dataType = TYPE_BYTES
};

int32_t SoftbusSessionManager::CreateSessionServer(const std::string &pkg)
{
    int32_t ret =
        ::CreateSessionServer(pkg.c_str(), std::string(CONFIG_SOFTBUS_SESSION_TAG).c_str(), &iSessionListener);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS || ret == REASON_EXIST,
        AVSESSION_ERROR, "CreateSessionServer failed ret[%{public}d]", ret);
    isSessionServerRunning_ = true;
    return AVSESSION_SUCCESS;
}

int32_t SoftbusSessionManager::RemoveSessionServer(const std::string &pkg)
{
    int32_t ret = ::RemoveSessionServer(pkg.c_str(), std::string(CONFIG_SOFTBUS_SESSION_TAG).c_str());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS || ret == REASON_EXIST,
        AVSESSION_ERROR, "RemoveSessionServer failed ret[%{public}d]", ret);
    isSessionServerRunning_ = false;
    return AVSESSION_SUCCESS;
}

int32_t SoftbusSessionManager::OpenSession(const std::string &deviceId, const std::string &groupId)
{
    CHECK_AND_RETURN_RET_LOG(isSessionServerRunning_,
        AVSESSION_ERROR,
        "the session server is do not running, unable to open session.");
    int32_t ret = ::OpenSession(std::string(CONFIG_SOFTBUS_SESSION_TAG).c_str(),
        std::string(CONFIG_SOFTBUS_SESSION_TAG).c_str(), deviceId.c_str(), groupId.c_str(), &sessionAttr);
    CHECK_AND_RETURN_RET_LOG(ret > 0, ret, "open session for device: %{public}d, return null session.", ret);
    SLOGI("open session for device: %{public}d, return entity session.", ret);
    return ret;
}

int32_t SoftbusSessionManager::CloseSession(int32_t sessionId)
{
    CHECK_AND_RETURN_RET_LOG(isSessionServerRunning_,
        AVSESSION_ERROR,
        "the session server is do not running, unable to close session.");
    ::CloseSession(sessionId);
    return AVSESSION_SUCCESS;
}

int32_t SoftbusSessionManager::SendMessage(int32_t sessionId, const std::string &data)
{
    if (sessionId <= 0 || data == "") {
        SLOGE("the params invalid, unable to send message by session.");
        return AVSESSION_ERROR;
    }
    int ret = ::SendMessage(sessionId, data.c_str(), data.length());
    return ret;
}

int32_t SoftbusSessionManager::SendBytes(int32_t sessionId, const std::string &data)
{
    if (sessionId <= 0 || data == "") {
        SLOGE("the params invalid, unable to send sendBytes by session.");
        return AVSESSION_ERROR;
    }
    int ret = ::SendBytes(sessionId, data.c_str(), data.length());
    return ret;
}

int32_t SoftbusSessionManager::ObtainPeerDeviceId(int32_t sessionId, std::string &deviceId)
{
    CHECK_AND_RETURN_RET_LOG(
        sessionId > 0, AVSESSION_ERROR, "the session is null, unable to obtain the peer device id.");
    char networkId[DEVICE_INFO_MAX_LENGTH] = { 0 };
    int ret = ::GetPeerDeviceId(sessionId, networkId, DEVICE_INFO_MAX_LENGTH);
    deviceId = networkId;
    return ret;
}

int32_t SoftbusSessionManager::GetPeerSessionName(int32_t sessionId, std::string &sessionName)
{
    CHECK_AND_RETURN_RET_LOG(
        sessionId > 0, AVSESSION_ERROR, "the session is null, unable to obtain the peer device id.");
    char peerSessionName[DEVICE_INFO_MAX_LENGTH] = { 0 };
    int ret = ::GetPeerSessionName(sessionId, peerSessionName, DEVICE_INFO_MAX_LENGTH);
    sessionName = peerSessionName;
    return ret;
}

bool SoftbusSessionManager::IsServerSide(int32_t sessionId)
{
    CHECK_AND_RETURN_RET_LOG(sessionId > 0, false,
        "the session is null, unable to judgement which side.");
    int ret = ::GetSessionSide(sessionId);
    if (ret == 0) {
        return true;
    }
    return false;
}

void SoftbusSessionManager::AddSessionListener(std::shared_ptr<SoftbusSessionListener> softbusSessionListener)
{
    if (softbusSessionListener == nullptr) {
        SLOGE("the session listener is null, unable to add to session listener list.");
        return;
    }
    std::lock_guard lockGuard(sessionLock_);
    sessionListeners_.clear();
    sessionListeners_.emplace_back(softbusSessionListener);
}

int32_t SoftbusSessionManager::OnSessionOpened(int32_t sessionId, int32_t result)
{
    if (result != AVSESSION_SUCCESS) {
        SLOGE("onSessionOpened failed.");
        return result;
    }
    std::lock_guard lockGuard(sessionLock_);
    for (auto listener : sessionListeners_) {
        listener->OnSessionOpened(sessionId);
    }
    return AVSESSION_SUCCESS;
}

void SoftbusSessionManager::OnSessionClosed(int32_t sessionId)
{
    std::lock_guard lockGuard(sessionLock_);
    for (auto listener : sessionListeners_) {
        listener->OnSessionClosed(sessionId);
    }
}

void SoftbusSessionManager::OnMessageReceived(int32_t sessionId, const std::string &data)
{
    std::lock_guard lockGuard(sessionLock_);
    for (auto listener : sessionListeners_) {
        listener->OnMessageReceived(sessionId, data);
    }
}

void SoftbusSessionManager::OnBytesReceived(int32_t sessionId, const std::string &data)
{
    std::lock_guard lockGuard(sessionLock_);
    for (auto listener : sessionListeners_) {
        listener->OnBytesReceived(sessionId, data);
    }
}
} // namespace OHOS::AVSession
