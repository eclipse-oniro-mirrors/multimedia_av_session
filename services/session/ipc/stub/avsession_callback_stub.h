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
#ifndef OHOS_AVSESSION_CALLBACK_STUB_H
#define OHOS_AVSESSION_CALLBACK_STUB_H

#include "iremote_stub.h"
#include "iavsession_callback.h"

namespace OHOS::AVSession {
class AVSessionCallbackStub : public IRemoteStub<IAVSessionCallback> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    static bool CheckInterfaceToken(MessageParcel& data);

    int32_t HandleOnAVCallAnswer(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnAVCallHangUp(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnAVCallToggleCallMute(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnPlay(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnPause(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnStop(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnPlayNext(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnFastForward(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnRewind(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnSeek(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnSetSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnSetLoopMode(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnToggleFavorite(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnMediaKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnOutputDeviceChange(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnCommonCommand(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnSkipToQueueItem(MessageParcel& data, MessageParcel& reply);
    using HandlerFunc = int32_t(AVSessionCallbackStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        &AVSessionCallbackStub::HandleOnPlay,
        &AVSessionCallbackStub::HandleOnPause,
        &AVSessionCallbackStub::HandleOnStop,
        &AVSessionCallbackStub::HandleOnPlayNext,
        &AVSessionCallbackStub::HandleOnPlayPrevious,
        &AVSessionCallbackStub::HandleOnFastForward,
        &AVSessionCallbackStub::HandleOnRewind,
        &AVSessionCallbackStub::HandleOnSeek,
        &AVSessionCallbackStub::HandleOnSetSpeed,
        &AVSessionCallbackStub::HandleOnSetLoopMode,
        &AVSessionCallbackStub::HandleOnToggleFavorite,
        &AVSessionCallbackStub::HandleOnMediaKeyEvent,
        &AVSessionCallbackStub::HandleOnOutputDeviceChange,
        &AVSessionCallbackStub::HandleOnCommonCommand,
        &AVSessionCallbackStub::HandleOnSkipToQueueItem,
        &AVSessionCallbackStub::HandleOnAVCallAnswer,
        &AVSessionCallbackStub::HandleOnAVCallHangUp,
        &AVSessionCallbackStub::HandleOnAVCallToggleCallMute,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_STUB_H
