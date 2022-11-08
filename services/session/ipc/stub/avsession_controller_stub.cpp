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

#include "avsession_controller_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
bool AVSessionControllerStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSessionController::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionControllerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code < CONTROLLER_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionControllerStub::HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply)
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

int32_t AVSessionControllerStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Destroy()), "write release() ret failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState state;
    int32_t ret = GetAVPlaybackState(state);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write AVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendControlCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::SendControlCommand");
    sptr<AVControlCommand> cmd = data.ReadParcelable<AVControlCommand>();
    if (cmd == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendCommand ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendControlCommand(*cmd)), "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVMetaData metaData;
    int32_t ret = GetAVMetaData(metaData);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&metaData), "write AVMetaData failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendAVKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::SendAVKeyEvent");
    std::shared_ptr<MMI::KeyEvent> event = MMI::KeyEvent::Create();
    if (event == nullptr) {
        SLOGI("malloc keyEvent failed");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_NO_MEMORY), "write SendAVKeyEvent ret failed");
        return ERR_NONE;
    }

    event->ReadFromParcel(data);
    if (!event->IsValid()) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendAVKeyEvent ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendAVKeyEvent(*(event.get()))),
            "write SendAVKeyEvent ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = GetLaunchAbility(ability);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&ability), "write LaunchAbility failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetValidCommands(MessageParcel& data, MessageParcel& reply)
{
    std::vector<int32_t> cmds;
    int32_t ret = GetValidCommands(cmds);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32Vector(cmds), "write int32 vector failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetMetaFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVMetaData::META_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetMetaFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVMetaData::MetaMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetMetaFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetPlaybackFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVPlaybackState::PLAYBACK_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetPlaybackFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not all 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVPlaybackState::PlaybackStateMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetPlaybackFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleIsSessionActive(MessageParcel& data, MessageParcel& reply)
{
    bool isActive = false;
    int32_t ret = IsSessionActive(isActive);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteBool(isActive), "write bool failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetSessionId(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteString(GetSessionId()), "write int32_t failed");
    return ERR_NONE;
}
} // OHOS::AVSession