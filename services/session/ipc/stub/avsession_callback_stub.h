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
        [SESSION_CALLBACK_ON_PLAY] = &AVSessionCallbackStub::HandleOnPlay,
        [SESSION_CALLBACK_ON_PAUSE] = &AVSessionCallbackStub::HandleOnPause,
        [SESSION_CALLBACK_ON_STOP] = &AVSessionCallbackStub::HandleOnStop,
        [SESSION_CALLBACK_ON_PLAY_NEXT] = &AVSessionCallbackStub::HandleOnPlayNext,
        [SESSION_CALLBACK_ON_PLAY_PREVIOUS] = &AVSessionCallbackStub::HandleOnPlayPrevious,
        [SESSION_CALLBACK_ON_FAST_FORWARD] = &AVSessionCallbackStub::HandleOnFastForward,
        [SESSION_CALLBACK_ON_REWIND] = &AVSessionCallbackStub::HandleOnRewind,
        [SESSION_CALLBACK_ON_SEEK] = &AVSessionCallbackStub::HandleOnSeek,
        [SESSION_CALLBACK_ON_SET_SPEED] = &AVSessionCallbackStub::HandleOnSetSpeed,
        [SESSION_CALLBACK_ON_SET_LOOPMODE] = &AVSessionCallbackStub::HandleOnSetLoopMode,
        [SESSION_CALLBACK_ON_TOGGLE_FAVORITE] = &AVSessionCallbackStub::HandleOnToggleFavorite,
        [SESSION_CALLBACK_ON_MEDIA_KEY_EVENT] = &AVSessionCallbackStub::HandleOnMediaKeyEvent,
        [SESSION_CALLBACK_ON_OUTPUT_DEVICE_CHANGE] = &AVSessionCallbackStub::HandleOnOutputDeviceChange,
        [SESSION_CALLBACK_ON_SEND_COMMON_COMMAND] = &AVSessionCallbackStub::HandleOnCommonCommand,
        [SESSION_CALLBACK_ON_SKIP_TO_QUEUE_ITEM] = &AVSessionCallbackStub::HandleOnSkipToQueueItem
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_STUB_H
