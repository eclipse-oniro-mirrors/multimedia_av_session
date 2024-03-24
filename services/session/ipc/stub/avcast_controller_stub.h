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

#ifndef OHOS_AVCAST_CONTROLLER_STUB_H
#define OHOS_AVCAST_CONTROLLER_STUB_H

#include "iavcast_controller.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVCastControllerStub : public IRemoteStub<IAVCastController> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) override
    {
        return 0;
    }

private:
    int32_t HandleSendControlCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStart(MessageParcel& data, MessageParcel& reply);
    
    int32_t HandlePrepare(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetDuration(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetCastAVPlayBackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetCurrentItem(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetValidCommands(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetDisplaySurface(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetCastPlaybackFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleProvideKeyResponse(MessageParcel& data, MessageParcel& reply)

    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleAddAvailableCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleRemoveAvailableCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t (AVCastControllerStub::*)(MessageParcel& data, MessageParcel& reply);
    static inline HandlerFunc handlers[] = {
        &AVCastControllerStub::HandleSendControlCommand,
        &AVCastControllerStub::HandleStart,
        &AVCastControllerStub::HandlePrepare,
        &AVCastControllerStub::HandleGetDuration,
        &AVCastControllerStub::HandleGetCastAVPlayBackState,
        &AVCastControllerStub::HandleGetCurrentItem,
        &AVCastControllerStub::HandleGetValidCommands,
        &AVCastControllerStub::HandleSetDisplaySurface,
        &AVCastControllerStub::HandleSetCastPlaybackFilter,
        &AVCastControllerStub::HandleProvideKeyResponse,
        &AVCastControllerStub::HandleRegisterCallbackInner,
        &AVCastControllerStub::HandleDestroy,
        &AVCastControllerStub::HandleAddAvailableCommand,
        &AVCastControllerStub::HandleRemoveAvailableCommand,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCAST_CONTROLLER_STUB_H
