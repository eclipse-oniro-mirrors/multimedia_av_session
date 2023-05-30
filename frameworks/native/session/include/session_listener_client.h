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

#ifndef OHOS_SESSION_LISTENER_CLIENT_H
#define OHOS_SESSION_LISTENER_CLIENT_H

#include <memory>

#include "session_listener_stub.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class SessionListenerClient : public SessionListenerStub {
public:
    explicit SessionListenerClient(const std::shared_ptr<SessionListener>& listener);

    void OnSessionCreate(const AVSessionDescriptor& descriptor) override;

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override;

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override;

    void OnAudioSessionChecked(const int32_t uid) override;

    void OnDeviceFound(const OutputDeviceInfo& castOutputDeviceInfo) override;
    
private:
    std::shared_ptr<SessionListener> listener_;
};
}
#endif // OHOS_SESSION_LISTENER_CLIENT_H