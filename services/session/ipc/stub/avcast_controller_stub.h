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

#ifndef OHOS_AVCAST_CONTROLLER_STUB_H
#define OHOS_AVCAST_CONTROLLER_STUB_H

#include <map>
#include "iavcast_controller.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVCastControllerStub : public IRemoteStub<IAVCastController> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) override
    {
        return 0;
    }

private:
    int32_t HandleSendControlCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStart(MessageParcel& data, MessageParcel& reply);
    
    int32_t HandlePrepare(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetDuration(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetCastAVPlayBackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetCurrentItem(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetValidCommands(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetDisplaySurface(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetCastPlaybackFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleProcessMediaKeyResponse(MessageParcel& data, MessageParcel& reply);

    int32_t HandleProvideKeyResponse(MessageParcel& data, MessageParcel& reply)

    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleAddAvailableCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleRemoveAvailableCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSendControlCommand(data, reply); }},
        {CAST_CONTROLLER_CMD_START,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStart(data, reply); }},
        {CAST_CONTROLLER_CMD_PREPARE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandlePrepare(data, reply); }},
        {CAST_CONTROLLER_CMD_GET_DURATION,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetDuration(data, reply); }},
        {CAST_CONTROLLER_CMD_GET_CAST_AV_PLAYBACK_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetCastAVPlayBackState(data, reply); }},
        {CAST_CONTROLLER_CMD_GET_CURRENT_ITEM,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetCurrentItem(data, reply); }},
        {CAST_CONTROLLER_CMD_GET_VALID_COMMANDS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetValidCommands(data, reply); }},
        {CAST_CONTROLLER_CMD_SET_DISPLAY_SURFACE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetDisplaySurface(data, reply); }},
        {CAST_CONTROLLER_CMD_SET_CAST_PLAYBACK_FILTER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetCastPlaybackFilter(data, reply); }},
        {CAST_CONTROLLER_CMD_PROVIDE_KEY_RESPONSE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleProcessMediaKeyResponse(data, reply); }},
        {CAST_CONTROLLER_CMD_REGISTER_CALLBACK,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRegisterCallbackInner(data, reply); }},
        {CAST_CONTROLLER_CMD_DESTROY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleDestroy(data, reply); }},
        {CAST_CONTROLLER_CMD_ADD_AVAILABLE_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleAddAvailableCommand(data, reply); }},
        {CAST_CONTROLLER_CMD_REMOVE_AVAILABLE_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRemoveAvailableCommand(data, reply); }}
    };
    std::map<uint32_t, std::string> mapCodeToFuncNameXCollie = {
        {CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND, "HandleSendControlCommand"},
        {CAST_CONTROLLER_CMD_START, "HandleStart"},
        {CAST_CONTROLLER_CMD_PREPARE, "HandlePrepare"},
        {CAST_CONTROLLER_CMD_GET_DURATION, "HandleGetDuration"},
        {CAST_CONTROLLER_CMD_GET_CAST_AV_PLAYBACK_STATE, "HandleGetCastAVPlayBackState"},
        {CAST_CONTROLLER_CMD_GET_CURRENT_ITEM, "HandleGetCurrentItem"},
        {CAST_CONTROLLER_CMD_GET_VALID_COMMANDS, "HandleGetValidCommands"},
        {CAST_CONTROLLER_CMD_SET_DISPLAY_SURFACE, "HandleSetDisplaySurface"},
        {CAST_CONTROLLER_CMD_SET_CAST_PLAYBACK_FILTER, "HandleSetCastPlaybackFilter"},
        {CAST_CONTROLLER_CMD_PROVIDE_KEY_RESPONSE, "HandleProvideKeyResponse"},
        {CAST_CONTROLLER_CMD_REGISTER_CALLBACK, "HandleRegisterCallbackInner"},
        {CAST_CONTROLLER_CMD_DESTROY, "HandleDestroy"},
        {CAST_CONTROLLER_CMD_ADD_AVAILABLE_COMMAND, "HandleAddAvailableCommand"},
        {CAST_CONTROLLER_CMD_REMOVE_AVAILABLE_COMMAND, "HandleRemoveAvailableCommand"}
    };
    const size_t defaultIpcCapacity = 1048576; // Increase the IPC default capacity(200K) to 1M
};
} // namespace OHOS::AVSession
#endif // OHOS_AVCAST_CONTROLLER_STUB_H
