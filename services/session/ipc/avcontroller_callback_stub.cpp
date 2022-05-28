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
#include "avcontroller_callback_stub.h"

#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVControllerCallbackStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = IAVControllerCallback::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVControllerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= CONTROLLER_CMD_ON_SESSION_RELEASE && code < CONTROLLER_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVControllerCallbackStub::HandleOnSessionRelease(MessageParcel &data, MessageParcel &reply)
{
    AVSessionDescriptor descriptor;
    CHECK_AND_RETURN_RET_LOG(descriptor.ReadFromParcel(data), ERR_NONE, "read AVSessionDescriptor failed");

    OnSessionRelease(descriptor);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnPlaybackStateChange(MessageParcel &data, MessageParcel &reply)
{
    sptr<AVPlaybackState> state = data.ReadParcelable<AVPlaybackState>();

    CHECK_AND_RETURN_RET_LOG(state != nullptr, ERR_NONE, "read PlaybackState failed");
    OnPlaybackStateUpdate(*state);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnMetadataChange(MessageParcel &data, MessageParcel &reply)
{
    sptr<AVMetaData> metaData = data.ReadParcelable<AVMetaData>();

    CHECK_AND_RETURN_RET_LOG(metaData != nullptr, ERR_NONE, "read MetaData failed");
    OnMetaDataUpdate(*metaData);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnActiveStateChange(MessageParcel &data, MessageParcel &reply)
{
    bool isActive = false;
    CHECK_AND_RETURN_RET_LOG(data.ReadBool(isActive), ERR_NONE, "read isActive failed");

    OnActiveStateChange(isActive);
    return ERR_NONE;
}
} // namespace OHOS::AVSession