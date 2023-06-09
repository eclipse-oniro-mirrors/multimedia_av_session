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

#include "avcast_controller_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "play_info_holder.h"

namespace OHOS::AVSession {
bool AVCastControllerStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVCastController::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVCastControllerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code < CAST_CONTROLLER_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVCastControllerStub::HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply)
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

int32_t AVCastControllerStub::HandleSendControlCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerStub::SendControlCommand");
    sptr<AVCastControlCommand> cmd = data.ReadParcelable<AVCastControlCommand>();
    if (cmd == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_UNMARSHALLING, "write SendCommand ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SendControlCommand(*cmd)), ERR_UNMARSHALLING, "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleStart(MessageParcel& data, MessageParcel& reply)
{
    sptr<PlayInfoHolder> playInfoHolder = data.ReadParcelable<PlayInfoHolder>();
    if (playInfoHolder == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write Start ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Start(*playInfoHolder)), ERR_NONE, "Write playInfoHolder failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleUpdate(MessageParcel& data, MessageParcel& reply)
{
    MediaInfo mediaInfo;
    CHECK_AND_RETURN_RET_LOG(mediaInfo.ReadFromParcel(data), ERR_UNMARSHALLING, "Write mediaInfo failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(UpdateMediaInfo(mediaInfo)), ERR_NONE, "Write mediaInfo failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetDuration(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(GetDuration()), "write int failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetSurfaceId(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteString(GetSurfaceId()), "write string failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetVolume(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(GetVolume()), "write int failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetLoopMode(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteDouble(GetLoopMode()), "write double failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetPlaySpeed(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(GetPlaySpeed()), "write int failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetCurrentTime(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(GetCurrentTime()), "write int failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Destroy()), "write release() ret failed");
    return ERR_NONE;
}
} // namespace OHOS::AVSession
