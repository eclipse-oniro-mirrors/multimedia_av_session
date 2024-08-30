/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
    if (code >= static_cast<uint32_t>(IAVCastControllerCallback::CAST_CONTROLLER_CMD_ON_CAST_PLAYBACK_STATE_CHANGE)
        && code < static_cast<uint32_t>(IAVCastControllerCallback::CAST_CONTROLLER_CMD_MAX)) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVCastControllerCallbackStub::HandleOnStateChange(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVPlaybackState> state = data.ReadParcelable<AVPlaybackState>();

    CHECK_AND_RETURN_RET_LOG(state != nullptr, ERR_NONE, "read PlaybackState failed");
    AVSESSION_TRACE_SYNC_START("AVCastControllerCallbackStub::HandleOnStateChange");
    SLOGI("HandleOnStateChange with state: %{public}d", state->GetState());
    OnCastPlaybackStateChange(*state);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnMediaItemChange(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerCallbackStub::HandleOnMediaItemChange");
    sptr<AVQueueItem> item = data.ReadParcelable<AVQueueItem>();
    CHECK_AND_RETURN_RET_LOG(item != nullptr, ERR_UNMARSHALLING, "read parcelable AVQueueItem failed");
    SLOGI("HandleOnMediaItemChange in");
    OnMediaItemChange(*item);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnPlayNext(MessageParcel& data, MessageParcel& reply)
{
    OnPlayNext();
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply)
{
    OnPlayPrevious();
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnSeekDone(MessageParcel& data, MessageParcel& reply)
{
    int32_t seekNumber;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(seekNumber), ERR_NONE, "read seekNumber failed");
    OnSeekDone(seekNumber);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnVideoSizeChange(MessageParcel& data, MessageParcel& reply)
{
    int32_t width;
    int32_t height;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(width), ERR_NONE, "read time failed");
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(height), ERR_NONE, "read time failed");
    OnVideoSizeChange(width, height);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnPlayerError(MessageParcel& data, MessageParcel& reply)
{
    int32_t errorCode;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(errorCode), ERR_NONE, "read time failed");
    std::string errorMsg;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(errorMsg), ERR_NONE, "read time failed");
    OnPlayerError(errorCode, errorMsg);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnEndOfStream(MessageParcel& data, MessageParcel& reply)
{
    int32_t isLooping;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(isLooping), ERR_NONE, "read isLooping failed");
    OnEndOfStream(isLooping);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnPlayRequest(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerCallbackStub::HandleOnPlayRequest");
    sptr<AVQueueItem> item = data.ReadParcelable<AVQueueItem>();
    CHECK_AND_RETURN_RET_LOG(item != nullptr, ERR_UNMARSHALLING, "read parcelable preload AVQueueItem failed");
    SLOGI("HandleOnPlayRequest in");
    OnPlayRequest(*item);
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnKeyRequest(MessageParcel& data, MessageParcel& reply)
{
    std::string assetId = data.ReadString();
    std::vector<uint8_t> request;
    uint32_t requestSize = static_cast<uint32_t>data.ReadInt32();
    uint32_t requestMaxLen = 8 * 1024 * 1024;
    CHECK_AND_RETURN_RET_LOG(requestSize <= requestMaxLen, AVSESSION_ERROR,
        "The size of request is too large.");
    if (requestSize != 0) {
        const uint8_t *requestBuf = static_cast<const uint8_t *>data.ReadBuffer(requestSize);
        if (requestBuf == nullptr) {
            SLOGE("AVCastControllerCallbackStub::HandleOnKeyRequest read request failed");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        request.assign(requestBuf, requestBuf + requestSize);
    }
    OnKeyRequest(assetId, request);
    SLOGI("HandleOnKeyRequest out");
    return ERR_NONE;
}

int32_t AVCastControllerCallbackStub::HandleOnCastValidCommandChanged(MessageParcel& data, MessageParcel& reply)
{
    std::vector<int32_t> cmds;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32Vector(&cmds), ERR_NONE, "read int32 vector failed");
    SLOGI("HandleOnCastValidCommandChanged cmd size:%{public}zd", cmds.size());
    OnCastValidCommandChanged(cmds);
    return ERR_NONE;
}
} // namespace OHOS::AVSession
