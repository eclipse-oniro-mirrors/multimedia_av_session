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

#ifndef OHOS_AVSESSION_MANAGER_IMPL_H
#define OHOS_AVSESSION_MANAGER_IMPL_H

#include <string>
#include <memory>
#include <mutex>

#include "iremote_object.h"
#include "av_session.h"
#include "avsession_service_proxy.h"
#include "avsession_info.h"
#include "client_death_stub.h"
#include "isession_listener.h"
#include "avsession_manager.h"
#include "avsession_controller.h"

namespace OHOS::AVSession {
class AVSessionManagerImpl : public AVSessionManager {
public:
    AVSessionManagerImpl();

    std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName) override;

    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t CreateController(const std::string& sessionId, std::shared_ptr<AVSessionController>& controller) override;

    int32_t CreateCastController(const std::string& sessionId,
        std::shared_ptr<AVCastController>& castController) override;

    int32_t GetActivatedSessionDescriptors(std::vector<AVSessionDescriptor>& activatedSessions) override;

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override;

    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t RegisterSessionListener(const std::shared_ptr<SessionListener>& listener) override;

    int32_t RegisterServiceDeathCallback(const DeathCallback& callback) override;

    int32_t UnregisterServiceDeathCallback() override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t CastAudio(const SessionToken& token,
                      const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t StartCastDiscovery(int32_t castDeviceCapability) override;

    int32_t StopCastDiscovery() override;

    int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t ReleaseCast(const std::string& sessionId) override;

private:
    sptr<AVSessionServiceProxy> GetService();

    void OnServiceDie();

    void RegisterClientDeathObserver();

    std::mutex lock_;
    sptr<AVSessionServiceProxy> service_;
    sptr<ISessionListener> listener_;
    sptr<ClientDeathStub> clientDeath_;
    DeathCallback deathCallback_;
};

class ServiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ServiceDeathRecipient(const std::function<void()>& callback);

    void OnRemoteDied(const wptr<IRemoteObject>& object) override;

private:
    std::function<void()> callback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_IMPL_H
