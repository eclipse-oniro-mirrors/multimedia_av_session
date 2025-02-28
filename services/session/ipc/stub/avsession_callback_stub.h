/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <map>
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
    int32_t HandleOnSetTargetLoopMode(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnToggleFavorite(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnMediaKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnOutputDeviceChange(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnCommonCommand(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnSkipToQueueItem(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnPlayFromAssetId(MessageParcel& data, MessageParcel& reply);
    int32_t HandleOnCastDisplayChange(MessageParcel& data, MessageParcel& reply);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {SESSION_CALLBACK_ON_PLAY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlay(data, reply); }},
        {SESSION_CALLBACK_ON_PAUSE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPause(data, reply); }},
        {SESSION_CALLBACK_ON_STOP,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnStop(data, reply); }},
        {SESSION_CALLBACK_ON_PLAY_NEXT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayNext(data, reply); }},
        {SESSION_CALLBACK_ON_PLAY_PREVIOUS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayPrevious(data, reply); }},
        {SESSION_CALLBACK_ON_FAST_FORWARD,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnFastForward(data, reply); }},
        {SESSION_CALLBACK_ON_REWIND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnRewind(data, reply); }},
        {SESSION_CALLBACK_ON_SEEK,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSeek(data, reply); }},
        {SESSION_CALLBACK_ON_SET_SPEED,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSetSpeed(data, reply); }},
        {SESSION_CALLBACK_ON_SET_LOOPMODE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSetLoopMode(data, reply); }},
        {SESSION_CALLBACK_ON_SET_TARGET_LOOPMODE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSetTargetLoopMode(data, reply); }},
        {SESSION_CALLBACK_ON_TOGGLE_FAVORITE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnToggleFavorite(data, reply); }},
        {SESSION_CALLBACK_ON_MEDIA_KEY_EVENT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnMediaKeyEvent(data, reply); }},
        {SESSION_CALLBACK_ON_OUTPUT_DEVICE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnOutputDeviceChange(data, reply); }},
        {SESSION_CALLBACK_ON_SEND_COMMON_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnCommonCommand(data, reply); }},
        {SESSION_CALLBACK_ON_SKIP_TO_QUEUE_ITEM,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSkipToQueueItem(data, reply); }},
        {SESSION_CALLBACK_ON_AVCALL_ANSWER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnAVCallAnswer(data, reply); }},
        {SESSION_CALLBACK_ON_AVCALL_HANGUP,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnAVCallHangUp(data, reply); }},
        {SESSION_CALLBACK_ON_AVCALL_TOGGLE_CALL_MUTE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnAVCallToggleCallMute(data, reply); }},
        {SESSION_CALLBACK_ON_PLAY_FROM_ASSETID,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayFromAssetId(data, reply); }},
        {SESSION_CALLBACK_ON_CAST_DISPLAY_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnCastDisplayChange(data, reply); }}
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CALLBACK_STUB_H
