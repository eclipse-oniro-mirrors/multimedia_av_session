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
    int32_t HandleGetHistoricalSessionDescriptors(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetHistoricalAVQueueInfos(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStartAVPlayback(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCreateControllerInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetAVCastControllerInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterSessionListener(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemAVKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemControlCommand(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterClientDeathObserver(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudio(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudioForAll(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRemoteCastAudio(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStartCastDiscovery(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStopCastDiscovery(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSetDiscoverable(MessageParcel& data, MessageParcel& reply);
    int32_t CheckBeforeHandleStartCast(MessageParcel& data, OutputDeviceInfo& outputDeviceInfo);
    int32_t HandleStartCast(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStopCast(MessageParcel& data, MessageParcel& reply);
    int32_t HandleClose(MessageParcel& data, MessageParcel& reply);
    static bool CheckInterfaceToken(MessageParcel& data);
    int32_t GetAVQueueInfosImgLength(std::vector<AVQueueInfo>& avQueueInfos);
    void MarshallingAVQueueInfos(MessageParcel &reply, const std::vector<AVQueueInfo>& avQueueInfos);
    void AVQueueInfoImgToBuffer(std::vector<AVQueueInfo>& avQueueInfos, unsigned char *buffer);

    using HandlerFunc = int32_t(AVSessionServiceStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        &AVSessionServiceStub::HandleCreateSessionInner,
        &AVSessionServiceStub::HandleGetAllSessionDescriptors,
        &AVSessionServiceStub::HandleGetSessionDescriptorsById,
        &AVSessionServiceStub::HandleGetHistoricalSessionDescriptors,
        &AVSessionServiceStub::HandleGetHistoricalAVQueueInfos,
        &AVSessionServiceStub::HandleStartAVPlayback,
        &AVSessionServiceStub::HandleCreateControllerInner,
        &AVSessionServiceStub::HandleGetAVCastControllerInner,
        &AVSessionServiceStub::HandleRegisterSessionListener,
        &AVSessionServiceStub::HandleSendSystemAVKeyEvent,
        &AVSessionServiceStub::HandleSendSystemControlCommand,
        &AVSessionServiceStub::HandleRegisterClientDeathObserver,
        &AVSessionServiceStub::HandleCastAudio,
        &AVSessionServiceStub::HandleCastAudioForAll,
        &AVSessionServiceStub::HandleRemoteCastAudio,
        &AVSessionServiceStub::HandleStartCastDiscovery,
        &AVSessionServiceStub::HandleStopCastDiscovery,
        &AVSessionServiceStub::HandleSetDiscoverable,
        &AVSessionServiceStub::HandleStartCast,
        &AVSessionServiceStub::HandleStopCast,
        &AVSessionServiceStub::HandleClose,
    };

    static constexpr int32_t RECEIVE_DEVICE_NUM_MAX = 10;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H
