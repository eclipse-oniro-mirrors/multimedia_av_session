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

#include "avsession_controller_stub.h"

#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVSessionControllerStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = IAVSessionController::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionControllerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= 0 && code < CONTROLLER_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionControllerStub::HandleRegisterCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write RegisterCallback ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(RegisterCallbackInner(remoteObject)),
            "write RegisterCallback ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleRelease(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Release()), "write release() ret failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVPlaybackState(MessageParcel &data, MessageParcel &reply)
{
    AVPlaybackState state;
    int32_t ret = GetAVPlaybackState(state);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write AVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendCommand(MessageParcel &data, MessageParcel &reply)
{
    sptr<AVControlCommand> cmd = data.ReadParcelable<AVControlCommand>();
    if (cmd == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendCommand ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendCommand(*cmd)), "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVMetaData(MessageParcel &data, MessageParcel &reply)
{
    AVMetaData metaData;
    int32_t ret = GetAVMetaData(metaData);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&metaData), "write AVMetaData failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendMediaKeyEvent(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<MMI::KeyEvent> event = MMI::KeyEvent::Create();
    if (event == nullptr) {
        SLOGD("malloc keyEvent failed");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_NO_MEMORY), "write SendMediaKeyEvent ret failed");
        return ERR_NONE;
    }

    event->ReadFromParcel(data);
    if (!event->IsValid()) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendMediaKeyEvent ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendMediaKeyEvent(*(event.get()))),
            "write SendMediaKeyEvent ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetLaunchAbility(MessageParcel &data, MessageParcel &reply)
{
    AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = GetLaunchAbility(ability);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&ability), "write LaunchAbility failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetSupportedCommand(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int32_t> cmds;
    int32_t ret = GetSupportedCommand(cmds);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32Vector(cmds), "write int32 vector failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetMetaFilter(MessageParcel &data, MessageParcel &reply)
{
    std::string str = data.ReadString();
    if (str.empty()) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetMetaFilter ret failed");
    } else {
        AVMetaData::MetaMaskType filter(str);
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SetMetaFilter(filter)), "write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleIsSessionActive(MessageParcel &data, MessageParcel &reply)
{
    bool isActive = false;
    int32_t ret = IsSessionActive(isActive);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ret), "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteBool(isActive), "write bool failed");
    }
    return ERR_NONE;
}
} // OHOS::AVSession