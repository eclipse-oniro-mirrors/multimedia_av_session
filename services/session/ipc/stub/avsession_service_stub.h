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
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int HandleCreateSessionInner(MessageParcel &data, MessageParcel &reply);
    int HandleGetAllSessionDescriptors(MessageParcel &data, MessageParcel &reply);
    int HandleGetSessionDescriptorsById(MessageParcel &data, MessageParcel &reply);
    int HandleCreateControllerInner(MessageParcel &data, MessageParcel &reply);
    int HandleRegisterSessionListener(MessageParcel &data, MessageParcel &reply);
    int HandleSendSystemAVKeyEvent(MessageParcel &data, MessageParcel &reply);
    int HandleSendSystemControlCommand(MessageParcel &data, MessageParcel &reply);
    int HandleRegisterClientDeathObserver(MessageParcel &data, MessageParcel &reply);
    int HandleCastAudio(MessageParcel &data, MessageParcel &reply);
    int HandleCastAudioForAll(MessageParcel &data, MessageParcel &reply);
    int HandleRemoteCastAudio(MessageParcel &data, MessageParcel &reply);
    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int(AVSessionServiceStub::*)(MessageParcel&, MessageParcel&);
    static inline HanlerFunc handlers[] = {
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
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H