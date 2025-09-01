/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "session_listener_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
SessionListenerClient::SessionListenerClient(const std::shared_ptr<SessionListener>& listener)
    : listener_(listener)
{
    SLOGD("construct");
}

SessionListenerClient::~SessionListenerClient()
{
    SLOGI("SessionListenerClient gone");
}

ErrCode SessionListenerClient::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    SLOGI("on session create for bundle %{public}s", descriptor.elementName_.GetBundleName().c_str());
    copiedListener->OnSessionCreate(descriptor);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnSessionRelease(descriptor);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnTopSessionChange(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnTopSessionChange(descriptor);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnAudioSessionChecked(const int32_t uid)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnAudioSessionChecked(uid);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnDeviceAvailable(castOutputDeviceInfo);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnDeviceLogEvent(const int32_t eventId, const int64_t param)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    DeviceLogEventCode eventCode = static_cast<DeviceLogEventCode>(eventId);
    CHECK_AND_RETURN_RET_LOG(eventCode > 0 &&  eventCode < DeviceLogEventCode::DEVICE_LOG_MAX,
        AVSESSION_ERROR, "there is no this eventCode");
    copiedListener->OnDeviceLogEvent(eventCode, param);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnDeviceOffline(const std::string& deviceId)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnDeviceOffline(deviceId);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnRemoteDistributedSessionChange(
    const std::vector<sptr<IRemoteObject>>& sessionControllers)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnRemoteDistributedSessionChange(sessionControllers);
    return AVSESSION_SUCCESS;
}

ErrCode SessionListenerClient::OnDeviceStateChange(const DeviceState& deviceState)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    copiedListener->OnDeviceStateChange(deviceState);
    return AVSESSION_SUCCESS;
}

AncoMediaSessionListenerImpl::AncoMediaSessionListenerImpl(const std::shared_ptr<AncoMediaSessionListener>& listener)
    : listener_(listener)
{
    SLOGD("construct");
}

AncoMediaSessionListenerImpl::~AncoMediaSessionListenerImpl()
{
    SLOGI("AncoMediaSessionListenerImpl destroy");
}

ErrCode AncoMediaSessionListenerImpl::OnStartAVPlayback(const std::string& bundleName)
{
    auto copiedListener = listener_;
    CHECK_AND_RETURN_RET_LOG(copiedListener, AVSESSION_ERROR, "listener_ is null");
    SLOGI("on StartAVPlayback for bundle %{public}s", bundleName.c_str());
    copiedListener->OnStartAVPlayback(bundleName);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
