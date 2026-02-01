/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_LITE
#include "iav_session.h"
#endif

#include "want.h"
#include "iavsession_service_ipc_interface_code.h"
#include "iclient_death.h"
#include "isession_listener.h"
#include "ianco_media_session_listener.h"
#include "key_event.h"
#include "avqueue_info.h"

namespace OHOS::AVSession {
class IAVSessionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVSessionService");

    enum RemoteServiceCommand {
        COMMAND_INVALID = -1,
        COMMAND_CAST_AUDIO = 0,
        COMMAND_CANCEL_CAST_AUDIO = 1,
        COMMAND_MAX = 2
    };

#ifndef CLIENT_LITE
    virtual sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                                   const AppExecFwk::ElementName& elementName) = 0;
    
    virtual int32_t CreateSessionInner(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName,
                                       sptr<IRemoteObject>& session) = 0;
#endif

    virtual int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) = 0;

    virtual int32_t GetSessionDescriptors(int32_t category, std::vector<AVSessionDescriptor>& descriptors) = 0;

    virtual int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId,
        AVSessionDescriptor& descriptor) = 0;

    virtual int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) = 0;
    
    virtual int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
                                              std::vector<AVQueueInfo>& avQueueInfos) = 0;
    
    virtual int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId,
        const std::string& moduleName) = 0;

    virtual int32_t RegisterAncoMediaSessionListener(const sptr<IAncoMediaSessionListener> &listener) = 0;

    virtual int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    virtual int32_t GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) = 0;
#endif

    virtual int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) = 0;

    virtual int32_t RegisterSessionListenerForAllUsers(const sptr<ISessionListener>& listener) = 0;

    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent, const AAFwk::Want &wantParam) = 0;

    virtual int32_t SendSystemControlCommand(const AVControlCommand& command) = 0;

    virtual int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) = 0;

    virtual int32_t CastAudio(const SessionToken& token,
                              const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;

    virtual int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;

    virtual int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                            std::string& output) = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    virtual int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) = 0;

    virtual int32_t StopCast(const SessionToken& sessionToken) = 0;

    virtual int32_t checkEnableCast(bool enable) = 0;
#endif

    virtual int32_t Close() = 0;

    virtual int32_t GetDistributedSessionControllersInner(const DistributedSessionType& sessionType,
        std::vector<sptr<IRemoteObject>>& sessionControllers) = 0;

#ifndef CLIENT_LITE
    virtual int32_t GetSessionInner(const AppExecFwk::ElementName& elementName,
        std::string& tag, sptr<IRemoteObject>& session) = 0;
#endif

    virtual int32_t IsDesktopLyricSupported(bool &isSupported) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_SERVICE_H
