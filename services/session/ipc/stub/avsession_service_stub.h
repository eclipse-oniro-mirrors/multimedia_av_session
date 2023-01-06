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

#ifndef OHOS_AVSESSION_SERVICE_STUB_H
#define OHOS_AVSESSION_SERVICE_STUB_H

#include "iavsession_service.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionServiceStub : public IRemoteStub<IAVSessionService> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t HandleCreateSessionInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetAllSessionDescriptors(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetSessionDescriptorsById(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCreateControllerInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterSessionListener(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemAVKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemControlCommand(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterClientDeathObserver(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudio(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudioForAll(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRemoteCastAudio(MessageParcel& data, MessageParcel& reply);
    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t(AVSessionServiceStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        [SERVICE_CMD_CREATE_SESSION] = &AVSessionServiceStub::HandleCreateSessionInner,
        [SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS] = &AVSessionServiceStub::HandleGetAllSessionDescriptors,
        [SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID] = &AVSessionServiceStub::HandleGetSessionDescriptorsById,
        [SERVICE_CMD_CREATE_CONTROLLER] = &AVSessionServiceStub::HandleCreateControllerInner,
        [SERVICE_CMD_REGISTER_SESSION_LISTENER] = &AVSessionServiceStub::HandleRegisterSessionListener,
        [SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT] = &AVSessionServiceStub::HandleSendSystemAVKeyEvent,
        [SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND] = &AVSessionServiceStub::HandleSendSystemControlCommand,
        [SERVICE_CMD_REGISTER_CLIENT_DEATH] = &AVSessionServiceStub::HandleRegisterClientDeathObserver,
        [SERVICE_CMD_CAST_AUDIO] = &AVSessionServiceStub::HandleCastAudio,
        [SERVICE_CMD_CAST_AUDIO_FOR_ALL] = &AVSessionServiceStub::HandleCastAudioForAll,
        [SERVICE_CMD_SEND_COMMAND_TO_REMOTE] = &AVSessionServiceStub::HandleRemoteCastAudio,
    };

    static constexpr int32_t RECEIVE_DEVICE_NUM_MAX = 10;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H