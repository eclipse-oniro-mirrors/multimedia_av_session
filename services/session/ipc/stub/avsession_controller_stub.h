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

#ifndef OHOS_AVSESSION_CONTROLLER_STUB_H
#define OHOS_AVSESSION_CONTROLLER_STUB_H

#include <map>
#include "iavsession_controller.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionControllerStub : public IRemoteStub<IAVSessionController> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) override
    {
        return 0;
    }

    int64_t GetRealPlaybackPosition() override
    {
        return 0;
    }

    bool IsDestroy() override
    {
        return true;
    }

private:
    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVCallState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVCallMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendControlCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendCommonCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSkipToQueueItem(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendAVKeyEvent(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetLaunchAbility(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetValidCommands(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallMetaFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallStateFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetMetaFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetPlaybackFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleIsSessionActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    static void DoMetadataImgCleanInStub(AVMetaData& data);
    static int32_t DoMetadataGetReplyInStub(AVMetaData& metaData, MessageParcel& reply);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {CONTROLLER_CMD_REGISTER_CALLBACK,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRegisterCallbackInner(data, reply); }},
        {CONTROLLER_CMD_DESTROY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleDestroy(data, reply); }},
        {CONTROLLER_CMD_GET_AV_PLAYBACK_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVPlaybackState(data, reply); }},
        {CONTROLLER_CMD_GET_AV_META_DATA,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVMetaData(data, reply); }},
        {CONTROLLER_CMD_SEND_AV_KEYEVENT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendAVKeyEvent(data, reply); }},
        {CONTROLLER_CMD_GET_LAUNCH_ABILITY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetLaunchAbility(data, reply); }},
        {CONTROLLER_CMD_GET_VALID_COMMANDS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetValidCommands(data, reply); }},
        {CONTROLLER_CMD_SEND_CONTROL_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendControlCommand(data, reply); }},
        {CONTROLLER_CMD_SEND_COMMON_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendCommonCommand(data, reply); }},
        {CONTROLLER_CMD_SET_META_FILTER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetMetaFilter(data, reply); }},
        {CONTROLLER_CMD_SET_PLAYBACK_FILTER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetPlaybackFilter(data, reply); }},
        {CONTROLLER_CMD_IS_SESSION_ACTIVE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleIsSessionActive(data, reply); }},
        {CONTROLLER_CMD_GET_SESSION_ID,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetSessionId(data, reply); }},
        {CONTROLLER_CMD_GET_AV_QUEUE_ITEMS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVQueueItems(data, reply); }},
        {CONTROLLER_CMD_GET_AV_QUEUE_TITLE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVQueueTitle(data, reply); }},
        {CONTROLLER_CMD_SKIP_TO_QUEUE_ITEM,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSkipToQueueItem(data, reply); }},
        {CONTROLLER_CMD_GET_EXTRAS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetExtras(data, reply); }},
        {CONTROLLER_CMD_GET_AVCALL_META_DATA,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVCallMetaData(data, reply); }},
        {CONTROLLER_CMD_SET_AVCALL_META_FILTER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVCallMetaFilter(data, reply); }},
        {CONTROLLER_CMD_GET_AVCALL_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVCallState(data, reply); }},
        {CONTROLLER_CMD_SET_AVCALL_STATE_FILTER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVCallStateFilter(data, reply); }}
    };
    std::map<uint32_t, std::string> mapCodeToFuncNameXCollie = {
        {CONTROLLER_CMD_REGISTER_CALLBACK, "HandleRegisterCallbackInner"},
        {CONTROLLER_CMD_DESTROY, "HandleDestroy"},
        {CONTROLLER_CMD_GET_AV_PLAYBACK_STATE, "HandleGetAVPlaybackState"},
        {CONTROLLER_CMD_GET_AV_META_DATA, "HandleGetAVMetaData"},
        {CONTROLLER_CMD_SEND_AV_KEYEVENT, "HandleSendAVKeyEvent"},
        {CONTROLLER_CMD_GET_LAUNCH_ABILITY, "HandleGetLaunchAbility"},
        {CONTROLLER_CMD_GET_VALID_COMMANDS, "HandleGetValidCommands"},
        {CONTROLLER_CMD_SEND_CONTROL_COMMAND, "HandleSendControlCommand"},
        {CONTROLLER_CMD_SEND_COMMON_COMMAND, "HandleSendCommonCommand"},
        {CONTROLLER_CMD_SET_META_FILTER, "HandleSetMetaFilter"},
        {CONTROLLER_CMD_SET_PLAYBACK_FILTER, "HandleSetPlaybackFilter"},
        {CONTROLLER_CMD_IS_SESSION_ACTIVE, "HandleIsSessionActive"},
        {CONTROLLER_CMD_GET_SESSION_ID, "HandleGetSessionId"},
        {CONTROLLER_CMD_GET_AV_QUEUE_ITEMS, "HandleGetAVQueueItems"},
        {CONTROLLER_CMD_GET_AV_QUEUE_TITLE, "HandleGetAVQueueTitle"},
        {CONTROLLER_CMD_SKIP_TO_QUEUE_ITEM, "HandleSkipToQueueItem"},
        {CONTROLLER_CMD_GET_EXTRAS, "HandleGetExtras"},
        {CONTROLLER_CMD_GET_AVCALL_META_DATA, "HandleGetAVCallMetaData"},
        {CONTROLLER_CMD_SET_AVCALL_META_FILTER, "HandleSetAVCallMetaFilter"},
        {CONTROLLER_CMD_GET_AVCALL_STATE, "HandleGetAVCallState"},
        {CONTROLLER_CMD_SET_AVCALL_STATE_FILTER, "HandleSetAVCallStateFilter"}
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CONTROLLER_STUB_H