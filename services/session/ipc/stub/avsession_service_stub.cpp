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

#include <cstdio>

#include "av_router.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "session_listener_proxy.h"
#include "client_death_proxy.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"
#include "parameter.h"
#include "parameters.h"
#include "avsession_service_stub.h"
#include "session_xcollie.h"
#include "permission_checker.h"

using namespace OHOS::AudioStandard;
namespace OHOS::AVSession {
bool AVSessionServiceStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSessionService::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionServiceStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
                                              MessageOption& option)
{
    if (code >= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_SESSION) &&
        code < static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX) &&
        code != static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_START_CAST)) {
        SessionXCollie sessionXCollie(mapCodeToFuncNameXCollie[code]);
    }
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_CREATE_SESSION) &&
        code < static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_MAX)) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionServiceStub::HandleCreateSessionInner(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CreateSessionInner");
    auto sessionTag = data.ReadString();
    auto sessionType = data.ReadInt32();
    sptr elementName = data.ReadParcelable<AppExecFwk::ElementName>();
    if (elementName == nullptr) {
        SLOGI("read element name failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    sptr<IRemoteObject> object;
    auto ret = CreateSessionInner(sessionTag, sessionType, *elementName, object);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteRemoteObject(object), "write object failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleGetAllSessionDescriptors(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("GetAllSessionDescriptors: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice getallsessiondescriptors checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = GetAllSessionDescriptors(descriptors);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(descriptors.size()), ERR_NONE, "write size failed");
    for (const auto& descriptor : descriptors) {
        if (!descriptor.WriteToParcel(reply)) {
            SLOGI("write descriptor failed");
            break;
        }
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleGetSessionDescriptorsById(MessageParcel& data, MessageParcel& reply)
{
    AVSessionDescriptor descriptor;
    int32_t ret = GetSessionDescriptorsBySessionId(data.ReadString(), descriptor);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(descriptor.WriteToParcel(reply), "write AVSessionDescriptor failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleGetHistoricalSessionDescriptors(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
        if (err != ERR_NONE) {
        SLOGE("GetHistoricalSessionDescriptors: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice getHistoricalSessionDescriptors checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = GetHistoricalSessionDescriptors(data.ReadInt32(), descriptors);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(descriptors.size()), ERR_NONE, "write size failed");
    for (const auto& descriptor : descriptors) {
        if (!descriptor.WriteToParcel(reply)) {
            SLOGI("write descriptor failed");
            break;
        }
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::GetAVQueueInfosImgLength(std::vector<AVQueueInfo>& avQueueInfos)
{
    int sumLength = 0;
    for (auto& avQueueInfo : avQueueInfos) {
        int avQueueImgLen = 0;
        std::shared_ptr<AVSessionPixelMap> pixelMap = avQueueInfo.GetAVQueueImage();
        if (pixelMap != nullptr) {
            avQueueImgLen = static_cast<int>((pixelMap->GetInnerImgBuffer()).size());
        }
        avQueueInfo.SetAVQueueLength(avQueueImgLen);
        sumLength += avQueueImgLen;
    }
    return sumLength;
}


void AVSessionServiceStub::MarshallingAVQueueInfos(MessageParcel &reply, const std::vector<AVQueueInfo>& avQueueInfos)
{
    CHECK_AND_RETURN_LOG(reply.WriteUint32(avQueueInfos.size()), "MarshallingAVQueueInfos size failed");
    for (const auto& avQueueInfo : avQueueInfos) {
        reply.WriteString(avQueueInfo.GetBundleName());
        reply.WriteString(avQueueInfo.GetAVQueueName());
        reply.WriteString(avQueueInfo.GetAVQueueId());
        reply.WriteString(avQueueInfo.GetAVQueueImageUri());
        reply.WriteUint32(avQueueInfo.GetAVQueueLength());
    }
}

void AVSessionServiceStub::AVQueueInfoImgToBuffer(std::vector<AVQueueInfo>& avQueueInfos, unsigned char *buffer)
{
    int k = 0;
    for (auto& avQueueInfo : avQueueInfos) {
        std::shared_ptr<AVSessionPixelMap> pixelMap = avQueueInfo.GetAVQueueImage();
        if (pixelMap != nullptr) {
            std::vector<uint8_t> imgBuffer = pixelMap->GetInnerImgBuffer();
            int length = avQueueInfo.GetAVQueueLength();
            for (int i = 0; i< length; i++, k++) {
                buffer[k] = imgBuffer[i];
            }
        }
    }
}

int32_t AVSessionServiceStub::HandleGetHistoricalAVQueueInfos(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("GetHistoricalAVQueueInfos: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice GetHistoricalAVQueueInfos checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    std::vector<AVQueueInfo> avQueueInfos;
    auto maxSize = data.ReadInt32();
    auto maxAppSize = data.ReadInt32();
    int32_t ret = GetHistoricalAVQueueInfos(maxSize, maxAppSize, avQueueInfos);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");

    int bufferLength = GetAVQueueInfosImgLength(avQueueInfos);
    CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(bufferLength), ERR_NONE, "write buffer length failed");
    if (bufferLength == 0) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteUint32(avQueueInfos.size()), ERR_NONE, "write size failed");
        for (const auto& avQueueInfo : avQueueInfos) {
            if (!avQueueInfo.Marshalling(reply)) {
                SLOGE("write avQueueInfo failed");
                break;
            }
        }
        return ERR_NONE;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[bufferLength];
    if (buffer == nullptr) {
        SLOGE("new buffer failed of length = %{public}d", bufferLength);
        return AVSESSION_ERROR;
    }

    MarshallingAVQueueInfos(reply, avQueueInfos);
    AVQueueInfoImgToBuffer(avQueueInfos, buffer);
    if (!reply.WriteRawData(buffer, bufferLength)) {
        SLOGE("fail to write parcel");
        delete[] buffer;
        return AVSESSION_ERROR;
    }

    delete[] buffer;
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStartAVPlayback(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StartAVPlayback: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StartAVPlayback checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    std::string bundleName = data.ReadString();
    std::string asserId = data.ReadString();
    int32_t ret = StartAVPlayback(bundleName, asserId);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleCreateControllerInner(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CreateControllerInner");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("CreateControllerInner: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingPid(), "SESSION_ID", data.ReadString(),
            "ERROR_MSG", "avsessionservice createcontrollerinner checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    sptr<IRemoteObject> object;
    int32_t ret = CreateControllerInner(data.ReadString(), object);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS || ret == ERR_CONTROLLER_IS_EXIST) {
        CHECK_AND_PRINT_LOG(reply.WriteRemoteObject(object), "write object failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleGetAVCastControllerInner(MessageParcel& data, MessageParcel& reply)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleGetAVCastControllerInner");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("GetAVCastControllerInner: CheckPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    sptr<IRemoteObject> object;
    int32_t ret = GetAVCastControllerInner(data.ReadString(), object);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteRemoteObject(object), "write object failed");
    }
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleRegisterSessionListener(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("RegisterSessionListener: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice registersessionlistener checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        SLOGI("read remote object failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto listener = iface_cast<SessionListenerProxy>(remoteObject);
    if (listener == nullptr) {
        SLOGI("RegisterSessionListener but iface_cast remote object failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_INVALID_PARAM), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!reply.WriteInt32(RegisterSessionListener(listener))) {
        SLOGI("reply write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleRegisterSessionListenerForAllUsers(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("RegisterSessionListenerForAllUsers: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice RegisterSessionListenerForAllUsers checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        SLOGI("read remote object failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto listener = iface_cast<SessionListenerProxy>(remoteObject);
    if (listener == nullptr) {
        SLOGI("RegisterSessionListenerForAllUsers but iface_cast remote object failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_INVALID_PARAM), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!reply.WriteInt32(RegisterSessionListenerForAllUsers(listener))) {
        SLOGI("reply write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleSendSystemAVKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::SendSystemAVKeyEvent");
    auto keyEvent = MMI::KeyEvent::Create();
    if (keyEvent == nullptr) {
        SLOGI("create keyEvent failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_NO_MEMORY), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!keyEvent->ReadFromParcel(data)) {
        SLOGI("read keyEvent failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!keyEvent->IsValid()) {
        SLOGI("keyEvent is not valid");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_INVALID_PARAM), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("SendSystemAVKeyEvent: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "KEY_CODE", keyEvent->GetKeyCode(), "KEY_ACTION", keyEvent->GetKeyAction(),
            "ERROR_MSG", "avsessionservice sendsystemavkeyevent checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!reply.WriteInt32(SendSystemAVKeyEvent(*keyEvent))) {
        SLOGI("reply write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleSendSystemControlCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::SendSystemControlCommand");
    sptr command = data.ReadParcelable<AVControlCommand>();
    if (command == nullptr) {
        SLOGI("read command failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "READ_PARCELABLE_FAILED",
            "ERROR_INFO", "handle send system control command read command failed");
        return ERR_NONE;
    }
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("SendSystemControlCommand: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingPid(), "CMD", command->GetCommand(),
            "ERROR_MSG", "avsessionservice sendsystemcontrolcommand checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    if (!reply.WriteInt32(SendSystemControlCommand(*command))) {
        SLOGI("reply write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleRegisterClientDeathObserver(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        SLOGI("read remote object failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto clientDeathObserver = iface_cast<ClientDeathProxy>(remoteObject);
    if (clientDeathObserver == nullptr) {
        SLOGI("iface_cast remote object failed");
        reply.WriteInt32(ERR_INVALID_PARAM);
        return ERR_NONE;
    }
    int32_t ret = RegisterClientDeathObserver(clientDeathObserver);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "register clientDeathObserver failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleClose(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("Close: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice Close checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    int32_t ret = Close();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "Close failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleCastAudio(MessageParcel& data, MessageParcel& reply)
{
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("CastAudio: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice CastAudio checkmission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CastAudio");
    SLOGI("start");
    SessionToken token {};
    token.sessionId = data.ReadString();
    token.pid = data.ReadInt32();
    token.uid = data.ReadInt32();
    int32_t deviceNum = data.ReadInt32();
    if (deviceNum > RECEIVE_DEVICE_NUM_MAX) {
        SLOGI("receive deviceNum over range");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_INVALID_PARAM), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }

    std::vector<AudioDeviceDescriptor> sinkAudioDescriptors;
    for (int i = 0; i < deviceNum; i++) {
        auto audioDeviceDescriptor = AudioDeviceDescriptor::UnmarshallingPtr(data);
        if (audioDeviceDescriptor == nullptr) {
            SLOGI("read AudioDeviceDescriptor failed");
            CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32 failed");
            return ERR_NONE;
        }
        SLOGI("networkId_: %{public}.6s, role %{public}d", (*audioDeviceDescriptor).networkId_.c_str(),
              static_cast<int32_t>((*audioDeviceDescriptor).deviceRole_));
        sinkAudioDescriptors.push_back(*audioDeviceDescriptor);
    }
    int32_t ret = CastAudio(token, sinkAudioDescriptors);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudio failed");
    SLOGI("CastAudio ret %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    SLOGI("success");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleCastAudioForAll(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::CastAudioForAll");
    SLOGI("CastAudioForAll start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("CastAudioForAll: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice CastAudioForAll checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    int32_t deviceNum = data.ReadInt32();
    if (deviceNum > RECEIVE_DEVICE_NUM_MAX) {
        SLOGI("receive deviceNum over range");
        reply.WriteInt32(ERR_INVALID_PARAM);
        return ERR_NONE;
    }

    std::vector<AudioDeviceDescriptor> sinkAudioDescriptors {};
    for (int i = 0; i < deviceNum; i++) {
        auto audioDeviceDescriptor = AudioDeviceDescriptor::UnmarshallingPtr(data);
        if (audioDeviceDescriptor == nullptr) {
            SLOGI("read AudioDeviceDescriptor failed");
            reply.WriteInt32(ERR_UNMARSHALLING);
            return ERR_NONE;
        }
        SLOGI("networkId_: %{public}.6s, role %{public}d", (*audioDeviceDescriptor).networkId_.c_str(),
              static_cast<int32_t>((*audioDeviceDescriptor).deviceRole_));
        sinkAudioDescriptors.push_back(*audioDeviceDescriptor);
    }
    int32_t ret = CastAudioForAll(sinkAudioDescriptors);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioForAll failed");
    SLOGI("CastAudioForAll ret %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleRemoteCastAudio(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::RemoteCastAudio");
    SLOGI("start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("ProcessCastAudioCommand: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice ProcessCastAudioCommand checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    auto command = static_cast<RemoteServiceCommand>(data.ReadInt32());
    std::string sessionInfo = data.ReadString();
    std::string output;
    int32_t ret = ProcessCastAudioCommand(command, sessionInfo, output);
    SLOGI("RemoteCastAudio ret %{public}d", ret);
    if (ret != AVSESSION_SUCCESS) {
        SLOGI("RemoteCastAudio failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteString(output), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStartCastDiscovery(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStartCastDiscovery");
    SLOGI("HandleStartCastDiscovery start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StartCastDiscovery: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", IPCSkeleton::GetCallingUid(),
            "CALLER_PID", IPCSkeleton::GetCallingPid(), "ERROR_MSG",
            "avsessionservice StartCastDiscovery checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    auto castDeviceCapability = data.ReadInt32();
    int32_t drmSchemesLen = data.ReadInt32();
    std::vector<std::string> drmSchemes;
    int32_t maxDrmSchemesLen = 10;
    CHECK_AND_RETURN_RET_LOG((drmSchemesLen >= 0) &&
        (drmSchemesLen <= maxDrmSchemesLen), ERR_NONE, "drmSchemesLen is illegal");
    for (int i = 0; i < drmSchemesLen; i++) {
        std::string drmScheme = data.ReadString();
        drmSchemes.emplace_back(drmScheme);
    }
    int32_t ret = AVRouter::GetInstance().StartCastDiscovery(castDeviceCapability, drmSchemes);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "HandleStartCastDiscovery failed");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStopCastDiscovery(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStopCastDiscovery");
    SLOGI("HandleStopCastDiscovery start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StopCastDiscovery: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", IPCSkeleton::GetCallingUid(),
            "CALLER_PID", IPCSkeleton::GetCallingPid(), "ERROR_MSG",
            "avsessionservice StopCastDiscovery checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t ret = AVRouter::GetInstance().StopCastDiscovery();
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "HandleStopCastDiscovery failed");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStartDeviceLogging(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStartDeviceLogging");
    SLOGI("HandleStartDeviceLogging start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("HandleStartDeviceLogging: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", IPCSkeleton::GetCallingUid(),
            "CALLER_PID", IPCSkeleton::GetCallingPid(), "ERROR_MSG",
            "avsessionservice StartDeviceLogging checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t fd = data.ReadFileDescriptor();
    uint32_t maxSize = data.ReadUint32();
    int32_t ret = AVRouter::GetInstance().StartDeviceLogging(fd, maxSize);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "HandleStartDeviceLogging failed");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStopDeviceLogging(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStopDeviceLogging");
    SLOGI("HandleStopDeviceLogging start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StopDeviceLogging: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", IPCSkeleton::GetCallingUid(),
            "CALLER_PID", IPCSkeleton::GetCallingPid(), "ERROR_MSG",
            "avsessionservice StopDeviceLogging checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t ret = AVRouter::GetInstance().StopDeviceLogging();
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "HandleStopDeviceLogging failed");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleSetDiscoverable(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleSetDiscoverable");
    SLOGI("HandleSetDiscoverable start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("SetDiscoverable: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", IPCSkeleton::GetCallingUid(),
            "CALLER_PID", IPCSkeleton::GetCallingPid(), "ERROR_MSG",
            "avsessionservice SetDiscoverable checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool enable;
    CHECK_AND_RETURN_RET_LOG(data.ReadBool(enable), AVSESSION_ERROR, "write enable info failed");
    int32_t ret = checkEnableCast(enable);

    bool is2in1 = system::GetBoolParameter("const.audio.volume_apply_to_all", false);
    SLOGI("GetDeviceEnableCast,Prop=%{public}d,enable=%{public}d", static_cast<int>(is2in1), static_cast<int>(enable));
    if (enable && is2in1 && ret) {
        AVRouter::GetInstance().SetDiscoverable(false);
        ret = AVRouter::GetInstance().SetDiscoverable(enable);
    }

    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "HandleSetDiscoverable failed");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::CheckBeforeHandleStartCast(MessageParcel& data, OutputDeviceInfo& outputDeviceInfo)
{
    DeviceInfo deviceInfo;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.castCategory_), false, "Read castCategory failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.deviceId_), false, "Read deviceId failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.deviceName_), false, "Read deviceName failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.deviceType_), false, "Read deviceType failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.ipAddress_), false, "Read ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.manufacturer_), false, "Read manufacturer failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.modelName_), false, "Read modelName failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.providerId_), false, "Read providerId failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.supportedProtocols_), false,
        "Read supportedProtocols failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.authenticationStatus_), false,
        "Read authenticationStatus failed");
    int32_t supportedDrmCapabilityLen = 0;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(supportedDrmCapabilityLen), false,
        "read supportedDrmCapabilityLen failed");
    int32_t maxSupportedDrmCapabilityLen = 10;
    CHECK_AND_RETURN_RET_LOG((supportedDrmCapabilityLen >= 0) &&
        (supportedDrmCapabilityLen <= maxSupportedDrmCapabilityLen), false, "supportedDrmCapabilityLen is illegal");
    std::vector<std::string> supportedDrmCapabilities;
    for (int i = 0; i < supportedDrmCapabilityLen; i++) {
        std::string supportedDrmCapability;
        CHECK_AND_RETURN_RET_LOG(data.ReadString(supportedDrmCapability), false,
            "read supportedDrmCapability failed");
        supportedDrmCapabilities.emplace_back(supportedDrmCapability);
    }
    deviceInfo.supportedDrmCapabilities_ = supportedDrmCapabilities;
    CHECK_AND_RETURN_RET_LOG(data.ReadBool(deviceInfo.isLegacy_), false, "Read isLegacy failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.mediumTypes_), false, "Read mediumTypes failed");
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    return true;
}

int32_t AVSessionServiceStub::HandleStartCast(MessageParcel& data, MessageParcel& reply)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStartCast");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(
        PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StartCast: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StartCast checkPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    SessionToken sessionToken {};
    sessionToken.sessionId = data.ReadString();
    sessionToken.pid = data.ReadInt32();
    sessionToken.uid = data.ReadInt32();

    OutputDeviceInfo outputDeviceInfo;
    int32_t deviceInfoSize;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfoSize), false, "write deviceInfoSize failed");

    if (deviceInfoSize > RECEIVE_DEVICE_NUM_MAX) {
        SLOGI("receive deviceNum over range");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_INVALID_PARAM), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    for (int i = 0; i < deviceInfoSize; i++) {
        if (!CheckBeforeHandleStartCast(data, outputDeviceInfo)) {
            SLOGE("check fail");
            return ERR_NONE;
        }
    }
    uint32_t callerToken = static_cast<uint32_t>(OHOS::IPCSkeleton::GetCallingTokenID());
    int temp = SetFirstCallerTokenID(callerToken);
    SLOGI("SetFirstCallerTokenID return %{public}d", temp);
    if (temp < 0) {
        SLOGE("SetFirstCallerTokenID fail");
    }
    int32_t ret = StartCast(sessionToken, outputDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "StartCast failed");
    SLOGI("StartCast ret %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    SLOGI("HandleStartCast success");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}

int32_t AVSessionServiceStub::HandleStopCast(MessageParcel& data, MessageParcel& reply)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("AVSessionServiceStub::HandleStopCast");
    SLOGI("HandleStopCast start");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("StopCast: CheckPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StopCast checkpermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    SessionToken sessionToken {};
    sessionToken.sessionId = data.ReadString();
    sessionToken.pid = data.ReadInt32();
    sessionToken.uid = data.ReadInt32();

    int32_t ret = StopCast(sessionToken);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "StopCast failed");
    SLOGI("StopCast ret %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    SLOGI("HandleStopCast success");
#else
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "WriteInt32 result failed");
#endif
    return ERR_NONE;
}
} // namespace OHOS::AVSession