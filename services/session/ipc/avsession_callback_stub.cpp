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

#include "avsession_callback_stub.h"
#include "avsession_errors.h"
#include "iavsession_callback.h"
#include "key_event.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
int32_t AVSessionCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption& option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= 0 && code < SESSION_CALLBACK_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool AVSessionCallbackStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSessionCallback::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionCallbackStub::HandleOnPlay(MessageParcel& data, MessageParcel& reply)
{
    OnPlay();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPause(MessageParcel& data, MessageParcel& reply)
{
    OnPause();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnStop(MessageParcel& data, MessageParcel& reply)
{
    OnStop();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPlayNext(MessageParcel& data, MessageParcel& reply)
{
    OnPlayNext();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply)
{
    OnPlayPrevious();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnFastForward(MessageParcel& data, MessageParcel& reply)
{
    OnFastForward();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnRewind(MessageParcel& data, MessageParcel& reply)
{
    OnRewind();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSeek(MessageParcel& data, MessageParcel& reply)
{
    int32_t time = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(time), ERR_NONE, "read time failed");
    OnSeek(time);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSetSpeed(MessageParcel& data, MessageParcel& reply)
{
    double speed = 0.0;
    CHECK_AND_RETURN_RET_LOG(data.ReadDouble(speed), ERR_NONE, "read speed failed");
    OnSetSpeed(speed);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSetLoopMode(MessageParcel& data, MessageParcel& reply)
{
    int32_t loopMode = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(loopMode), ERR_NONE, "read loopMode failed");
    OnSetLoopMode(loopMode);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnToggleFavorite(MessageParcel& data, MessageParcel& reply)
{
    std::string mediaId;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(mediaId), ERR_NONE, "read mediaId failed");
    OnToggleFavorite(mediaId);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnMediaKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    auto keyEvent = MMI::KeyEvent::Create();
    CHECK_AND_RETURN_RET_LOG((*keyEvent).ReadFromParcel(data), ERR_NONE, "read keyEvent failed");
    OnMediaKeyEvent(*keyEvent);
    return ERR_NONE;
}
} // namespace OHOS::AVSession