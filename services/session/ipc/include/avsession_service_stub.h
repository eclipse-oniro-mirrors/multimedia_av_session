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

#ifndef OHOS_AVSESSION_SERVICE_STUB_H
#define OHOS_AVSESSION_SERVICE_STUB_H

#include "iavsession_service.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionServiceStub : public IRemoteStub<IAVSessionService> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int HandleCreateSessionInner(MessageParcel &data, MessageParcel &reply);
    int HandleGetSessionInner(MessageParcel &data, MessageParcel &reply);
    int HandleGetAllSessionDescriptors(MessageParcel &data, MessageParcel &reply);
    int HandleCreateControllerInner(MessageParcel &data, MessageParcel &reply);
    int HandleGetControllerInner(MessageParcel &data, MessageParcel &reply);
    int HandleGetAllControllersInner(MessageParcel &data, MessageParcel &reply);
    int HandleRegisterSessionListenerInner(MessageParcel &data, MessageParcel &reply);
    int HandleSendSystemMediaKeyEvent(MessageParcel &data, MessageParcel &reply);
    int HandleSetSystemMediaVolume(MessageParcel &data, MessageParcel &reply);
    int HandleRegisterClientDeathObserver(MessageParcel &data, MessageParcel &reply);
    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int(AVSessionServiceStub::*)(MessageParcel&, MessageParcel&);
    static inline HanlerFunc handlers[] = {
        [SERVICE_CMD_CREATE_SESSION] = &AVSessionServiceStub::HandleCreateSessionInner,
        [SERVICE_CMD_GET_SESSION] = &AVSessionServiceStub::HandleGetSessionInner,
        [SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS] = &AVSessionServiceStub::HandleGetAllSessionDescriptors,
        [SERVICE_CMD_CREATE_CONTROLLER] = &AVSessionServiceStub::HandleCreateControllerInner,
        [SERVICE_CMD_GET_CONTROLLER] = &AVSessionServiceStub::HandleGetControllerInner,
        [SERVICE_CMD_GET_ALL_CONTROLLERS] = &AVSessionServiceStub::HandleGetAllControllersInner,
        [SERVICE_CMD_REGISTER_SESSION_LISTENER] = &AVSessionServiceStub::HandleRegisterSessionListenerInner,
        [SERVICE_CMD_SEND_SYSTEM_MEDIA_KEY_EVENT] = &AVSessionServiceStub::HandleSendSystemMediaKeyEvent,
        [SERVICE_CMD_SET_SYSTEM_MEDIA_VOLUEM] = &AVSessionServiceStub::HandleSetSystemMediaVolume,
        [SERVICE_CMD_REGISTER_CLIENT_DEATH] = &AVSessionServiceStub::HandleRegisterClientDeathObserver
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H