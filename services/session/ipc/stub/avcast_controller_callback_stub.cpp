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
#include "avcast_controller_callback_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
bool AVCastControllerCallbackStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVCastControllerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
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

int32_t AVCastControllerCallbackStub::HandleOnStateChange(MessageParcel& data, MessageParcel& reply)
{
    AVCastPlayerState castPlayerState;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(castPlayerState.castPlayerState_), false, "Read castPlayerState failed");
    AVSESSION_TRACE_SYNC_START("AVCastControllerCallbackStub::OnStateChanged");
    OnStateChanged(castPlayerState);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnVolumeChange(MessageParcel& data, MessageParcel& reply)
{
    int32_t volume;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(volume), ERR_NONE, "read volume failed");
    OnVolumeChanged(volume);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnSeekDone(MessageParcel& data, MessageParcel& reply)
{
    int32_t seek;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(seek), ERR_NONE, "read seek failed");
    OnSeekDone(seek);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnPlaySpeedChanged(MessageParcel& data, MessageParcel& reply)
{
    int32_t speed;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(speed), ERR_NONE, "read speed failed");
    OnPlaySpeedChanged(speed);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnTimeUpdate(MessageParcel& data, MessageParcel& reply)
{
    int32_t time;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(time), ERR_NONE, "read time failed");
    OnTimeUpdate(time);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnError(MessageParcel& data, MessageParcel& reply)
{
    int32_t errorCode;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(errorCode), ERR_NONE, "read time failed");
    std::string errorMsg;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(errorMsg), ERR_NONE, "read time failed");
    OnPlayerError(errorCode, errorMsg);
    return ERR_NONE;
}
} // namespace OHOS::AVSession
