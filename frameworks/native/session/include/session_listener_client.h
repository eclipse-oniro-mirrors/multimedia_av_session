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

#ifndef OHOS_SESSION_LISTENER_CLIENT_H
#define OHOS_SESSION_LISTENER_CLIENT_H

#include <memory>

#include "session_listener_stub.h"
#include "anco_media_session_listener_stub.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class SessionListenerClient : public SessionListenerStub {
public:
    explicit SessionListenerClient(const std::shared_ptr<SessionListener>& listener);

    ~SessionListenerClient();

    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override;

    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override;

    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override;

    ErrCode OnAudioSessionChecked(const int32_t uid) override;

    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override;

    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override;

    ErrCode OnDeviceOffline(const std::string& deviceId) override;

    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override;

    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override;

    ErrCode OnActiveSessionChanged(const std::vector<AVSessionDescriptor> &descriptors) override;
private:
    std::shared_ptr<SessionListener> listener_;
};

class AncoMediaSessionListenerImpl : public AncoMediaSessionListenerStub {
public:
    explicit AncoMediaSessionListenerImpl(const std::shared_ptr<AncoMediaSessionListener>& listener);

    ~AncoMediaSessionListenerImpl();

    ErrCode OnStartAVPlayback(const std::string& bundleName) override;
private:
    std::shared_ptr<AncoMediaSessionListener> listener_;
};
}
#endif // OHOS_SESSION_LISTENER_CLIENT_H