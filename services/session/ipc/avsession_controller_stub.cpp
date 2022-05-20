/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "avcontroller_callback_proxy.h"
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

int32_t AVSessionControllerStub::RegisterCallback(std::shared_ptr<AVControllerCallback> &callback)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleRegisterCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        reply.WriteInt32(AVSESSION_ERROR);
        return ERR_NONE;
    }

    auto callback = iface_cast<AVControllerCallbackProxy>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(RegisterCallbackInner(callback)), ERR_MARSHALLING, "write int failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleRelease(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Release()), ERR_MARSHALLING, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVPlaybackState(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleSendCommand(MessageParcel &data, MessageParcel &reply)
{
    AVControlCommand *cmd = AVControlCommand::Unmarshalling(data);
    int32_t ret = ERR_NONE;
    if (!reply.WriteInt32(SendCommand(*cmd))) {
        SLOGE("write int32 failed");
        ret = ERR_MARSHALLING;
    }
    delete cmd;
    return ret;
}

int32_t AVSessionControllerStub::HandleGetAVMetaData(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleGetAVVolumeInfo(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleSendMediaKeyEvent(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleGetLaunchAbility(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t AVSessionControllerStub::HandleGetSupportedCommand(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int32_t> cmds;
    int32_t ret = GetSupportedCommand(cmds);
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32Vector(cmds), ERR_MARSHALLING, "write int32 vector failed");
    }
    return ret;
}

int32_t AVSessionControllerStub::HandleSetMetaFilter(MessageParcel &data, MessageParcel &reply)
{
    std::string str = data.ReadString();
    std::bitset<AVMetadata::META_KEY_MAX> filter(str);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetMetaFilter(filter)), ERR_MARSHALLING, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleIsSessionActive(MessageParcel &data, MessageParcel &reply)
{
    bool isActive = false;
    int32_t ret = IsSessionActive(isActive);
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteBool(isActive), ERR_MARSHALLING, "write bool failed");
    }
    return ret;
}
}