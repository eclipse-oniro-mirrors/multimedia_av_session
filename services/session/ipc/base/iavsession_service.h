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

#ifndef OHOS_IAVSESSION_SERVICE_H
#define OHOS_IAVSESSION_SERVICE_H

#include "audio_system_manager.h"
#include "iremote_broker.h"
#include "iav_session.h"
#include "iclient_death.h"
#include "isession_listener.h"
#include "key_event.h"

namespace OHOS::AVSession {
class IAVSessionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVSessionService");

    enum {
        SERVICE_CMD_CREATE_SESSION,
        SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS,
        SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID,
        SERVICE_CMD_CREATE_CONTROLLER,
        SERVICE_CMD_REGISTER_SESSION_LISTENER,
        SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT,
        SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND,
        SERVICE_CMD_REGISTER_CLIENT_DEATH,
        SERVICE_CMD_CAST_AUDIO,
        SERVICE_CMD_CAST_AUDIO_FOR_ALL,
        SERVICE_CMD_SEND_COMMAND_TO_REMOTE,
        SERVICE_CMD_MAX
    };

    enum RemoteServiceCommand {
        COMMAND_INVALID = -1,
        COMMAND_CAST_AUDIO = 0,
        COMMAND_CANCEL_CAST_AUDIO = 1,
        COMMAND_MAX = 2
    };

    virtual sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                                   const AppExecFwk::ElementName& elementName) = 0;

    virtual int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) = 0;

    virtual int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId,
        AVSessionDescriptor& descriptor) = 0;

    virtual int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) = 0;

    virtual int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) = 0;

    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    virtual int32_t SendSystemControlCommand(const AVControlCommand& command) = 0;

    virtual int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) = 0;

    virtual int32_t CastAudio(const SessionToken& token,
                              const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;

    virtual int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;

    virtual int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                            std::string& output) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_SERVICE_H