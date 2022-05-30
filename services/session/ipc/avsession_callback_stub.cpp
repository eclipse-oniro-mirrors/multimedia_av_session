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
int AVSessionCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
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

int AVSessionCallbackStub::HandleOnPlay(MessageParcel& data, MessageParcel& reply)
{
    OnPlay();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnPause(MessageParcel& data, MessageParcel& reply)
{
    OnPause();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnStop(MessageParcel& data, MessageParcel& reply)
{
    OnStop();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnPlayNext(MessageParcel& data, MessageParcel& reply)
{
    OnPlayNext();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply)
{
    OnPlayPrevious();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnFastForward(MessageParcel& data, MessageParcel& reply)
{
    OnFastForward();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnRewind(MessageParcel& data, MessageParcel& reply)
{
    OnRewind();
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnSeek(MessageParcel& data, MessageParcel& reply)
{
    int32_t time = data.ReadInt64();
    OnSeek(time);
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnSetSpeed(MessageParcel& data, MessageParcel& reply)
{
    int32_t speed = data.ReadInt32();
    OnSetSpeed(speed);
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnSetLoopMode(MessageParcel& data, MessageParcel& reply)
{
    int32_t loopMode = data.ReadInt32();
    OnSetLoopMode(loopMode);
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnToggleFavorite(MessageParcel& data, MessageParcel& reply)
{
    std::string mediald(data.ReadString());
    OnToggleFavorite(mediald);
    return ERR_NONE;
}

int AVSessionCallbackStub::HandleOnMediaKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    auto keyEvent = MMI::KeyEvent::Create();
    (*keyEvent).ReadFromParcel(data);
    OnMediaKeyEvent(*keyEvent);
    return ERR_NONE;
}
} // namespace OHOS::AVSession