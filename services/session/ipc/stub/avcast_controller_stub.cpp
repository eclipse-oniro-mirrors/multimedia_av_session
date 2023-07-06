/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "media_info_holder.h"

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
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING),
            ERR_UNMARSHALLING, "write SendCommand ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SendControlCommand(*cmd)),
            ERR_UNMARSHALLING, "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleStart(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVQueueItem> avQueueItem = data.ReadParcelable<AVQueueItem>();
    AVFileDescriptor avFileDescriptor;
    avFileDescriptor.fd_ = data.ReadFileDescriptor();
    if (avQueueItem == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write Start ret failed");
    } else {
        avQueueItem->GetDescription()->SetFdSrc(avFileDescriptor);
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Start(*avQueueItem)),
            ERR_NONE, "Write mediaInfoHolder failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandlePrepare(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVQueueItem> avQueueItem = data.ReadParcelable<AVQueueItem>();
    if (avQueueItem == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write prepare ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Prepare(*avQueueItem)),
            ERR_NONE, "Write mediaInfoHolder failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetDuration(MessageParcel& data, MessageParcel& reply)
{
    int32_t duration;
    int32_t ret = GetDuration(duration);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_UNMARSHALLING, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(duration), ERR_UNMARSHALLING, "write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetCastAVPlayBackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState state;
    int32_t ret = GetCastAVPlaybackState(state);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write CastAVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetCurrentItem(MessageParcel& data, MessageParcel& reply)
{
    AVQueueItem currentItem;
    int32_t ret = GetCurrentItem(currentItem);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&currentItem), ERR_NONE, "Write currentItem failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleSetDisplaySurface(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::HandleSetDisplaySurface");
    auto surfaceId = data.ReadString();
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetDisplaySurface(surfaceId)),
        ERR_NONE, "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleSetCastPlaybackFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVPlaybackState::PLAYBACK_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetCastPlaybackFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not all 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVPlaybackState::PlaybackStateMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetCastPlaybackFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Destroy()), "write release() ret failed");
    return ERR_NONE;
}
} // namespace OHOS::AVSession