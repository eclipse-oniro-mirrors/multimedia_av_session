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

#ifndef OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H
#define OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H

#include "iavcast_controller_callback.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVCastControllerCallbackStub : public IRemoteStub<IAVCastControllerCallback> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:

    int32_t HandleOnStateChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnVolumeChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnSeekDone(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlaySpeedChanged(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnTimeUpdate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnError(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t (AVCastControllerCallbackStub::*)(MessageParcel& data, MessageParcel& reply);
    static inline HandlerFunc handlers[] = {
        &AVCastControllerCallbackStub::HandleOnStateChange,
        &AVCastControllerCallbackStub::HandleOnVolumeChange,
        &AVCastControllerCallbackStub::HandleOnSeekDone,
        &AVCastControllerCallbackStub::HandleOnPlaySpeedChanged,
        &AVCastControllerCallbackStub::HandleOnTimeUpdate,
        &AVCastControllerCallbackStub::HandleOnError,
    };
};
}
#endif // OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H
