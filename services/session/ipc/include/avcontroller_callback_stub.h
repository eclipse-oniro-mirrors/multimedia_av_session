/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVCONTROLLER_CALLBACK_STUB_H
#define OHOS_AVCONTROLLER_CALLBACK_STUB_H

#include "iavcontroller_callback.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVControllerCallbackStub : public IRemoteStub<IAVControllerCallback> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:

    int32_t HandleOnSessionRelease(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnPlaybackStateChange(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnMetadataChange(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnVolumeInfoChange(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnActiveStateChange(MessageParcel &data, MessageParcel &reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int32_t (AVControllerCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    static inline HanlerFunc handlers[] = {
        [CONTROLLER_CMD_ON_SESSION_RELEASE] = &AVControllerCallbackStub::HandleOnSessionRelease,
        [CONTROLLER_CMD_ON_PLAYBACK_STATE_CHANGE] = &AVControllerCallbackStub::HandleOnPlaybackStateChange,
        [CONTROLLER_CMD_ON_METADATA_CHANGE] = &AVControllerCallbackStub::HandleOnMetadataChange,
        [CONTROLLER_CMD_ON_VOLUME_INFO_CHANGE] = &AVControllerCallbackStub::HandleOnVolumeInfoChange,
        [CONTROLLER_CMD_ON_ACTIVE_STATE_CHANGE] = &AVControllerCallbackStub::HandleOnActiveStateChange,
    };
};
}
#endif // OHOS_AVCONTROLLER_CALLBACK_STUB_H