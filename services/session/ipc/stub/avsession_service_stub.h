/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <map>
#include "iavsession_service.h"
#include "iremote_stub.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

namespace OHOS::AVSession {
class AVSessionServiceStub : public IRemoteStub<IAVSessionService> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t HandleGetSessionInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCreateSessionInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetAllSessionDescriptors(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetSessionDescriptors(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetSessionDescriptorsById(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetHistoricalSessionDescriptors(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetHistoricalAVQueueInfos(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStartAVPlayback(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterAncoMediaSessionListener(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCreateControllerInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleGetAVCastControllerInner(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterSessionListener(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterSessionListenerForAllUsers(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemAVKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSendSystemControlCommand(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRegisterClientDeathObserver(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudio(MessageParcel& data, MessageParcel& reply);
    int32_t HandleCastAudioForAll(MessageParcel& data, MessageParcel& reply);
    int32_t HandleRemoteCastAudio(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStartCastDiscovery(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStopCastDiscovery(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStartDeviceLogging(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStopDeviceLogging(MessageParcel& data, MessageParcel& reply);
    int32_t HandleSetDiscoverable(MessageParcel& data, MessageParcel& reply);
    int32_t CheckBeforeHandleStartCast(MessageParcel& data, OutputDeviceInfo& outputDeviceInfo);
    int32_t HandleStartCast(MessageParcel& data, MessageParcel& reply);
    int32_t HandleStopCast(MessageParcel& data, MessageParcel& reply);
    int32_t HandleClose(MessageParcel& data, MessageParcel& reply);
    static bool CheckInterfaceToken(MessageParcel& data);
    int32_t GetAVQueueInfosImgLength(std::vector<AVQueueInfo>& avQueueInfos);
    void MarshallingAVQueueInfos(MessageParcel &reply, const std::vector<AVQueueInfo>& avQueueInfos);
    void AVQueueInfoImgToBuffer(std::vector<AVQueueInfo>& avQueueInfos, unsigned char *buffer);
    int32_t HandleGetDistributedSessionControllersInner(MessageParcel& data, MessageParcel& reply);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetSessionInner(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_SESSION),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleCreateSessionInner(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAllSessionDescriptors(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION_DESCRIPTORS),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetSessionDescriptors(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID),
            [this](MessageParcel& data, MessageParcel& reply)
            { return HandleGetSessionDescriptorsById(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_SESSION_DESCRIPTORS),
            [this](MessageParcel& data, MessageParcel& reply)
            { return HandleGetHistoricalSessionDescriptors(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_AVQUEUE_INFOS),
            [this](MessageParcel& data, MessageParcel& reply)
            { return HandleGetHistoricalAVQueueInfos(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_AV_PLAYBACK),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStartAVPlayback(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_CONTROLLER),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleCreateControllerInner(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_AV_CAST_CONTROLLER),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVCastControllerInner(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_SESSION_LISTENER),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRegisterSessionListener(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_SESSION_LISTENER_FOR_ALL_USERS),
            [this](MessageParcel& data, MessageParcel& reply)
            { return HandleRegisterSessionListenerForAllUsers(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendSystemAVKeyEvent(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendSystemControlCommand(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_CLIENT_DEATH),
            [this](MessageParcel& data, MessageParcel& reply)
            { return HandleRegisterClientDeathObserver(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleCastAudio(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO_FOR_ALL),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleCastAudioForAll(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_COMMAND_TO_REMOTE),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRemoteCastAudio(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_DEVICE_LOGGING),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStartDeviceLogging(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_DEVICE_LOGGING),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStopDeviceLogging(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST_DISCOVERY),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStartCastDiscovery(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST_DISCOVERY),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStopCastDiscovery(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SET_DISCOVERYABLE),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetDiscoverable(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStartCast(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStopCast(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CLOSE),
            [this](MessageParcel& data, MessageParcel& reply) { return HandleClose(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_DISTRIBUTED_SESSION_CONTROLLERS),
            [this](MessageParcel& data, MessageParcel& reply) {
            return HandleGetDistributedSessionControllersInner(data, reply); }},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_ANCO_MEDIA_SESSION_LISTENER),
            [this](MessageParcel& data, MessageParcel& reply) {
            return HandleRegisterAncoMediaSessionListener(data, reply); }}
    };
    std::map<uint32_t, std::string> mapCodeToFuncNameXCollie = {
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION),
            "HandleGetSessionInner"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_SESSION),
            "HandleCreateSessionInner"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS),
            "HandleGetAllSessionDescriptors"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION_DESCRIPTORS),
            "HandleGetSessionDescriptors"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID),
            "HandleGetSessionDescriptorsById"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_SESSION_DESCRIPTORS),
            "HandleGetHistoricalSessionDescriptors"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_HISTORY_AVQUEUE_INFOS),
            "HandleGetHistoricalAVQueueInfos"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_AV_PLAYBACK),
            "HandleStartAVPlayback"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_CONTROLLER),
            "HandleCreateControllerInner"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_AV_CAST_CONTROLLER),
            "HandleGetAVCastControllerInner"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_SESSION_LISTENER),
            "HandleRegisterSessionListener"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_SESSION_LISTENER_FOR_ALL_USERS),
            "HandleRegisterSessionListenerForAllUsers"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT),
            "HandleSendSystemAVKeyEvent"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND),
            "HandleSendSystemControlCommand"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_CLIENT_DEATH),
            "HandleRegisterClientDeathObserver"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO),
            "HandleCastAudio"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CAST_AUDIO_FOR_ALL),
            "HandleCastAudioForAll"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_COMMAND_TO_REMOTE),
            "HandleRemoteCastAudio"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_DEVICE_LOGGING),
            "HandleStartDeviceLogging"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_DEVICE_LOGGING),
            "HandleStopDeviceLogging"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST_DISCOVERY),
            "HandleStartCastDiscovery"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST_DISCOVERY),
            "HandleStopCastDiscovery"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SET_DISCOVERYABLE),
            "HandleSetDiscoverable"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST),
            "HandleStartCast"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_STOP_CAST),
            "HandleStopCast"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CLOSE),
            "HandleClose"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_GET_DISTRIBUTED_SESSION_CONTROLLERS),
            "HandleGetDistributedSessionControllersInner"},
        {static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_REGISTER_ANCO_MEDIA_SESSION_LISTENER),
            "HandleRegisterAncoMediaSessionListener"}
    };

    static constexpr int32_t RECEIVE_DEVICE_NUM_MAX = 10;
    static constexpr int32_t audioBrokerUid = 5557;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H
