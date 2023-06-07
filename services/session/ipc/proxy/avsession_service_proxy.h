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

#ifndef OHOS_AVSESSION_SERVICE_PROXY_H
#define OHOS_AVSESSION_SERVICE_PROXY_H

#include "iavsession_service.h"
#include "iremote_proxy.h"
#include "av_session.h"
#include "avcast_controller.h"
#include "avsession_controller.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
class AVSessionServiceProxy : public IRemoteProxy<IAVSessionService> {
public:
    explicit AVSessionServiceProxy(const sptr<IRemoteObject>& impl);

    std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName);

    sptr<IRemoteObject> CreateSessionInner(const std::string& tag, int32_t type,
                                           const AppExecFwk::ElementName& elementName) override;

    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override;

    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t CreateController(const std::string& sessionId, std::shared_ptr<AVSessionController>& controller);

    int32_t CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override;

    int32_t GetAVCastController(const std::string& sessionId, std::shared_ptr<AVCastController>& controller);

    int32_t GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object) override;

    int32_t RegisterSessionListener(const sptr<ISessionListener>& listener) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t RegisterClientDeathObserver(const sptr<IClientDeath>& observer) override;

    int32_t CastAudio(const SessionToken& token,
                      const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                    std::string& output) override
    {
        return AVSESSION_SUCCESS;
    }

    int32_t StartCastDiscovery(int32_t castDeviceCapability);

    int32_t StopCastDiscovery();

    int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t StopCast(const std::string& sessionId) override;

private:
    static inline BrokerDelegator<AVSessionServiceProxy> delegator_;
};
} // namespace OHOS
#endif // OHOS_AVSESSION_SERVICE_PROXY_H
