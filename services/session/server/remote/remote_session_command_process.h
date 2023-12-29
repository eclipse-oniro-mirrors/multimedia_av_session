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

#ifndef OHOS_REMOTE_SESSION_COMMAND_PROCESS_H
#define OHOS_REMOTE_SESSION_COMMAND_PROCESS_H

#include "iavsession_service.h"
#include "iremote_proxy.h"
#include "av_session.h"
#include "avsession_controller.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
class RemoteSessionCommandProcess : public IRemoteProxy<IAVSessionService> {
public:
    explicit RemoteSessionCommandProcess(const sptr<IRemoteObject>& impl);

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const AppExecFwk::ElementName& elementName) override
    {
        return nullptr;
    }

    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) override
    {
        return AVSESSION_SUCCESS;
    }
    
    int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
      std::vector<AVQueueInfo>& avQueueInfo) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override
    {
        return AVSESSION_SUCCESS;
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override
    {
        return AVSESSION_SUCCESS;
    }
#endif

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t SendSystemControlCommand(const AVControlCommand& command) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t CastAudio(const SessionToken& token,
                      const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                    std::string& output) override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t StopCast(const SessionToken& sessionToken) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t checkEnableCast(bool enable) override
    {
        return AVSESSION_SUCCESS;
    }
#endif

    int32_t Close(void) override
    {
        return AVSESSION_SUCCESS;
    }
private:
    static inline BrokerDelegator<RemoteSessionCommandProcess> delegator_;
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_COMMAND_PROCESS_H