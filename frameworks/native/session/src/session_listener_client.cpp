/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "avsession_log.h"

namespace OHOS::AVSession {
SessionListenerClient::SessionListenerClient(const std::shared_ptr<SessionListener>& listener)
    : listener_(listener)
{
    SLOGD("construct");
}

void SessionListenerClient::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnSessionCreate(descriptor);
    }
}

void SessionListenerClient::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnSessionRelease(descriptor);
    }
}

void SessionListenerClient::OnTopSessionChange(const AVSessionDescriptor& descriptor)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnTopSessionChange(descriptor);
    }
}

void SessionListenerClient::OnAudioSessionChecked(const int32_t uid)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnAudioSessionChecked(uid);
    }
}

void SessionListenerClient::OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnDeviceAvailable(castOutputDeviceInfo);
    }
}

void SessionListenerClient::OnDeviceOffline(const std::string& deviceId)
{
    auto copiedListener = listener_;
    if (copiedListener) {
        copiedListener->OnDeviceOffline(deviceId);
    }
}
} // namespace OHOS::AVSession
