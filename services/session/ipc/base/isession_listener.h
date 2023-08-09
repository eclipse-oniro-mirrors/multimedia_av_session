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

#ifndef OHOS_ISESSION_LISTENER_H
#define OHOS_ISESSION_LISTENER_H

#include "iremote_broker.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class ISessionListener : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.ISessionListener");

    enum {
        LISTENER_CMD_ON_CREATE,
        LISTENER_CMD_ON_RELEASE,
        LISTENER_CMD_TOP_CHANGED,
        LISTENER_CMD_AUDIO_CHECKED,
        LISTENER_CMD_DEVICE_AVAILABLE,
        LISTENER_CMD_DEVICE_OFFLINE,
        LISTENER_CMD_MAX
    };

    virtual void OnSessionCreate(const AVSessionDescriptor& descriptor) = 0;

    virtual void OnSessionRelease(const AVSessionDescriptor& descriptor) = 0;

    virtual void OnTopSessionChange(const AVSessionDescriptor& descriptor) = 0;

    virtual void OnAudioSessionChecked(const int32_t uid) = 0;

    virtual void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) = 0;

    virtual void OnDeviceOffline(const std::string& deviceId) = 0;
};
}
#endif // OHOS_ISESSION_LISTENER_H
