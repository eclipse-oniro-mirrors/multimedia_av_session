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

#ifndef OHOS_AVCONTROLLER_CALLBACK_STUB_H
#define OHOS_AVCONTROLLER_CALLBACK_STUB_H

#include <map>
#include "iavcontroller_callback.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVControllerCallbackStub : public IRemoteStub<IAVControllerCallback> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:

    int32_t HandleOnSessionDestroy(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnAVCallMetadataChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnAVCallStateChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnPlaybackStateChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnMetadataChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnActiveStateChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnValidCommandChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnOutputDeviceChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnSessionEventChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnQueueItemsChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnQueueTitleChange(MessageParcel& data, MessageParcel& reply);

    int32_t HandleOnExtrasChange(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {CONTROLLER_CMD_ON_SESSION_DESTROY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSessionDestroy(data, reply); }},
        {CONTROLLER_CMD_ON_PLAYBACK_STATE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnPlaybackStateChange(data, reply); }},
        {CONTROLLER_CMD_ON_METADATA_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnMetadataChange(data, reply); }},
        {CONTROLLER_CMD_ON_ACTIVE_STATE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnActiveStateChange(data, reply); }},
        {CONTROLLER_CMD_ON_VALID_COMMAND_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnValidCommandChange(data, reply); }},
        {CONTROLLER_CMD_ON_OUTPUT_DEVICE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnOutputDeviceChange(data, reply); }},
        {CONTROLLER_CMD_ON_SET_SESSION_EVENT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnSessionEventChange(data, reply); }},
        {CONTROLLER_CMD_ON_QUEUE_ITEMS_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnQueueItemsChange(data, reply); }},
        {CONTROLLER_CMD_ON_QUEUE_TITLE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnQueueTitleChange(data, reply); }},
        {CONTROLLER_CMD_ON_SET_EXTRAS_EVENT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnExtrasChange(data, reply); }},
        {CONTROLLER_CMD_ON_AVCALL_METADATA_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnAVCallMetadataChange(data, reply); }},
        {CONTROLLER_CMD_ON_AVCALL_STATE_CHANGE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleOnAVCallStateChange(data, reply); }}
    };

    int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;

    std::mutex onMetadataChangeLock_;
    std::mutex onPlaybackChangeLock_;
    std::mutex onValidCommandChangeLock_;
};
}
#endif // OHOS_AVCONTROLLER_CALLBACK_STUB_H