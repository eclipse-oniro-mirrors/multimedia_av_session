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

#ifndef OHOS_AVSESSION_STUB_H
#define OHOS_AVSESSION_STUB_H

#include <map>
#include "iav_session.h"
#include "iremote_stub.h"
#include "want_agent.h"
#include "want_params.h"
#include "avsession_log.h"
#include "avsession_errors.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller.h"
#endif

namespace OHOS::AVSession {
class AVSessionStub : public IRemoteStub<IAVSession> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) override
    {
        return ERR_NONE;
    }

    std::shared_ptr<AVSessionController> GetController() override
    {
        return nullptr;
    }
    
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override
    {
        return nullptr;
    }
#endif

private:
    int32_t HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetSessionType(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t SetImageData(AVMetaData& meta, const char *buffer, int twoImageLength);

    int32_t HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetController(MessageParcel& data, MessageParcel& reply);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t HandleGetAVCastController(MessageParcel& data, MessageParcel& reply);

    int32_t HandleReleaseCast(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStartCastDisplayListener(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStopCastDisplayListener(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAllCastDisplays(MessageParcel& data, MessageParcel& reply);
#endif

    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleActivate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDeactivate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleIsActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    int32_t HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDeleteSupportCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetSessionEvent(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply);
    
    int32_t HandleSetAVQueueItems(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = std::function<int32_t(MessageParcel&, MessageParcel&)>;
    std::map<uint32_t, HandlerFunc> handlers = {
        {SESSION_CMD_GET_SESSION_ID,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetSessionId(data, reply); }},
        {SESSION_CMD_GET_SESSION_TYPE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetSessionType(data, reply); }},
        {SESSION_CMD_GET_META_DATA,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVMetaData(data, reply); }},
        {SESSION_CMD_SET_META_DATA,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVMetaData(data, reply); }},
        {SESSION_CMD_GET_PLAYBACK_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVPlaybackState(data, reply); }},
        {SESSION_CMD_SET_PLAYBACK_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVPlaybackState(data, reply); }},
        {SESSION_CMD_GET_QUEUE_ITEMS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVQueueItems(data, reply); }},
        {SESSION_CMD_SET_QUEUE_ITEMS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVQueueItems(data, reply); }},
        {SESSION_CMD_GET_QUEUE_TITLE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVQueueTitle(data, reply); }},
        {SESSION_CMD_SET_QUEUE_TITLE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVQueueTitle(data, reply); }},
        {SESSION_CMD_GET_EXTRAS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetExtras(data, reply); }},
        {SESSION_CMD_SET_EXTRAS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetExtras(data, reply); }},
        {SESSION_CMD_SET_LAUNCH_ABILITY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetLaunchAbility(data, reply); }},
        {SESSION_CMD_GET_CONTROLLER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetController(data, reply); }},
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        {SESSION_CMD_GET_AVCAST_CONTROLLER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAVCastController(data, reply); }},
        {SESSION_CMD_START_CAST_DISPLAY_LISTENER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStartCastDisplayListener(data, reply); }},
        {SESSION_CMD_STOP_CAST_DISPLAY_LISTENER,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleStopCastDisplayListener(data, reply); }},
        {SESSION_CMD_GET_ALL_CAST_DISPLAYS,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleGetAllCastDisplays(data, reply); }},
#endif
        {SESSION_CMD_REGISTER_CALLBACK,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleRegisterCallbackInner(data, reply); }},
        {SESSION_CMD_ACTIVATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleActivate(data, reply); }},
        {SESSION_CMD_DEACTIVATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleDeactivate(data, reply); }},
        {SESSION_CMD_ISACTIVE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleIsActive(data, reply); }},
        {SESSION_CMD_DESTROY,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleDestroy(data, reply); }},
        {SESSION_CMD_ADD_SUPPORT_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleAddSupportCommand(data, reply); }},
        {SESSION_CMD_DELETE_SUPPORT_COMMAND,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleDeleteSupportCommand(data, reply); }},
        {SESSION_CMD_SET_SESSION_EVENT,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetSessionEvent(data, reply); }},
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        {SESSION_CMD_RELEASE_CAST,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleReleaseCast(data, reply); }},
#endif
        {SESSION_CMD_SET_AVCALL_META_DATA,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVCallMetaData(data, reply); }},
        {SESSION_CMD_SET_AVCALL_STATE,
            [this](MessageParcel& data, MessageParcel& reply) { return HandleSetAVCallState(data, reply); }}
    };
    std::map<uint32_t, std::string> mapCodeToFuncNameXCollie = {
        {SESSION_CMD_GET_SESSION_ID, "HandleGetSessionId"},
        {SESSION_CMD_GET_SESSION_TYPE, "HandleGetSessionType"},
        {SESSION_CMD_GET_META_DATA, "HandleGetAVMetaData"},
        {SESSION_CMD_SET_META_DATA, "HandleSetAVMetaData"},
        {SESSION_CMD_GET_PLAYBACK_STATE, "HandleGetAVPlaybackState"},
        {SESSION_CMD_SET_PLAYBACK_STATE, "HandleSetAVPlaybackState"},
        {SESSION_CMD_GET_QUEUE_ITEMS, "HandleGetAVQueueItems"},
        {SESSION_CMD_SET_QUEUE_ITEMS, "HandleSetAVQueueItems"},
        {SESSION_CMD_GET_QUEUE_TITLE, "HandleGetAVQueueTitle"},
        {SESSION_CMD_SET_QUEUE_TITLE, "HandleSetAVQueueTitle"},
        {SESSION_CMD_GET_EXTRAS, "HandleGetExtras"},
        {SESSION_CMD_SET_EXTRAS, "HandleSetExtras"},
        {SESSION_CMD_SET_LAUNCH_ABILITY, "HandleSetLaunchAbility"},
        {SESSION_CMD_GET_CONTROLLER, "HandleGetController"},
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        {SESSION_CMD_GET_AVCAST_CONTROLLER, "HandleGetAVCastController"},
        {SESSION_CMD_START_CAST_DISPLAY_LISTENER, "HandleStartCastDisplayListener"},
        {SESSION_CMD_STOP_CAST_DISPLAY_LISTENER, "HandleStopCastDisplayListener"},
        {SESSION_CMD_GET_ALL_CAST_DISPLAYS, "HandleGetAllCastDisplays"},
#endif
        {SESSION_CMD_REGISTER_CALLBACK, "HandleRegisterCallbackInner"},
        {SESSION_CMD_ACTIVATE, "HandleActivate"},
        {SESSION_CMD_DEACTIVATE, "HandleDeactivate"},
        {SESSION_CMD_ISACTIVE, "HandleIsActive"},
        {SESSION_CMD_DESTROY, "HandleDestroy"},
        {SESSION_CMD_ADD_SUPPORT_COMMAND, "HandleAddSupportCommand"},
        {SESSION_CMD_DELETE_SUPPORT_COMMAND, "HandleDeleteSupportCommand"},
        {SESSION_CMD_SET_SESSION_EVENT, "HandleSetSessionEvent"},
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        {SESSION_CMD_RELEASE_CAST, "HandleReleaseCast"},
#endif
        {SESSION_CMD_SET_AVCALL_META_DATA, "HandleSetAVCallMetaData"},
        {SESSION_CMD_SET_AVCALL_STATE, "HandleSetAVCallState"}
    };

    int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;
};
}
#endif // OHOS_AVSESSION_STUB_H
