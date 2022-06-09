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

#ifndef OHOS_AVSESSION_CONTROLLER_STUB_H
#define OHOS_AVSESSION_CONTROLLER_STUB_H

#include "iavsession_controller.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionControllerStub : public IRemoteStub<IAVSessionController> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback> &callback) override
    {
        return 0;
    }

    uint64_t GetRealPlaybackPosition() override
    {
        return 0;
    }

private:
    int32_t HandleRegisterCallbackInner(MessageParcel &data, MessageParcel &reply);

    int32_t HandleRelease(MessageParcel &data, MessageParcel &reply);

    int32_t HandleGetAVPlaybackState(MessageParcel &data, MessageParcel &reply);

    int32_t HandleSendControlCommand(MessageParcel &data, MessageParcel &reply);

    int32_t HandleGetAVMetaData(MessageParcel &data, MessageParcel &reply);

    int32_t HandleSendAVKeyEvent(MessageParcel &data, MessageParcel &reply);

    int32_t HandleGetLaunchAbility(MessageParcel &data, MessageParcel &reply);

    int32_t HandleGetValidCommands(MessageParcel &data, MessageParcel &reply);

    int32_t HandleSetMetaFilter(MessageParcel &data, MessageParcel &reply);

    int32_t HandleIsSessionActive(MessageParcel &data, MessageParcel &reply);

    int32_t HandleGetSessionId(MessageParcel &data, MessageParcel &reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int32_t (AVSessionControllerStub::*)(MessageParcel &data, MessageParcel &reply);
    static inline HanlerFunc handlers[] = {
        [CONTROLLER_CMD_REGISTER_CALLBACK] = &AVSessionControllerStub::HandleRegisterCallbackInner,
        [CONTROLLER_CMD_RELEASE] = &AVSessionControllerStub::HandleRelease,
        [CONTROLLER_CMD_GET_AV_PLAYBACK_STATE] = &AVSessionControllerStub::HandleGetAVPlaybackState,
        [CONTROLLER_CMD_SEND_CONTROL_COMMAND] = &AVSessionControllerStub::HandleSendControlCommand,
        [CONTROLLER_CMD_GET_AV_META_DATA] = &AVSessionControllerStub::HandleGetAVMetaData,
        [CONTROLLER_CMD_SEND_AV_KEYEVENT] = &AVSessionControllerStub::HandleSendAVKeyEvent,
        [CONTROLLER_CMD_GET_LAUNCH_ABILITY] = &AVSessionControllerStub::HandleGetLaunchAbility,
        [CONTROLLER_CMD_GET_VALID_COMMANDS] = &AVSessionControllerStub::HandleGetValidCommands,
        [CONTROLLER_CMD_SET_META_FILTER] = &AVSessionControllerStub::HandleSetMetaFilter,
        [CONTROLLER_CMD_IS_SESSION_ACTIVE] = &AVSessionControllerStub::HandleIsSessionActive,
        [CONTROLLER_CMD_GET_SESSION_ID] = &AVSessionControllerStub::HandleGetSessionId,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CONTROLLER_STUB_H