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

#ifndef OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H
#define OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H

#include <map>
#include "iavcast_controller_callback.h"
#include "iremote_stub.h"
#include "av_shared_memory_helper.h"

namespace OHOS::AVSession {
class AVCastControllerCallbackStub : public IRemoteStub<IAVCastControllerCallback> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:

    int32_t HandleOnStateChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnMediaItemChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlayNext(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnSeekDone(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnVideoSizeChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlayerError(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnEndOfStream(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlayRequest(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnKeyRequest(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnCastValidCommandChanged(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnDataSrcRead(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {CAST_CONTROLLER_CMD_ON_CAST_PLAYBACK_STATE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnStateChange(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_MEDIA_ITEM_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnMediaItemChange(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_PLAY_NEXT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayNext(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_PLAY_PREVIOUS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayPrevious(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_SEEK_DONE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSeekDone(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_VIDEO_SIZE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnVideoSizeChange(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_ERROR,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayerError(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_END_OF_STREAM,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnEndOfStream(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_PLAY_REQUEST,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlayRequest(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_KEY_REQUEST,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnKeyRequest(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_VALID_COMMAND_CHANGED,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnCastValidCommandChanged(data, reply); }},
        {CAST_CONTROLLER_CMD_ON_DATA_SRC_READ,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnDataSrcRead(data, reply); }}
    };
};
}
#endif // OHOS_AVCAST_CONTROLLER_CALLBACK_STUB_H
