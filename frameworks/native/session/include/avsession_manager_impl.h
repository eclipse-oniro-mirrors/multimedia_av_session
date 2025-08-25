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

#ifndef OHOS_AVSESSION_MANAGER_IMPL_H
#define OHOS_AVSESSION_MANAGER_IMPL_H

#include <string>
#include <memory>
#include <mutex>

#include "iremote_object.h"
#include "iservice_registry.h"
#include "system_ability_status_change_stub.h"
#include "av_session.h"
#include "avsession_service_proxy.h"
#include "avsession_info.h"
#include "client_death_stub.h"
#include "isession_listener.h"
#include "avsession_manager.h"
#include "avsession_controller.h"

namespace OHOS::AVSession {
class ServiceDeathRecipient;
class ServiceStatusListener;
class AVSessionManagerImpl : public AVSessionManager {
public:
    AVSessionManagerImpl();

    static void DetachCallback();

    std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName) override;

    int32_t CreateSession(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName,
                          std::shared_ptr<AVSession>& session) override;

    int32_t CreateSessionWithExtra(const std::string& tag, int32_t type, const std::string& extraInfo,
                                   const AppExecFwk::ElementName& elementName,
                                   std::shared_ptr<AVSession>& session) override;

    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) override;

    int32_t CreateController(const std::string& sessionId, std::shared_ptr<AVSessionController>& controller) override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t GetAVCastController(const std::string& sessionId,
        std::shared_ptr<AVCastController>& castController) override;
#endif

    int32_t GetActivatedSessionDescriptors(std::vector<AVSessionDescriptor>& activatedSessions) override;

    int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) override;

    int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) override;
    
    int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
        std::vector<AVQueueInfo>& avQueueInfos) override;

    int32_t RegisterSessionListener(const std::shared_ptr<SessionListener>& listener) override;

    int32_t RegisterSessionListenerForAllUsers(const std::shared_ptr<SessionListener>& listener) override;

    int32_t RegisterServiceDeathCallback(const DeathCallback& callback) override;

    int32_t UnregisterServiceDeathCallback() override;

    int32_t RegisterServiceStartCallback(const std::function<void()> serviceStartCallback) override;

    int32_t UnregisterServiceStartCallback() override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) override;

    int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent, const AAFwk::Want &wantParam) override;

    int32_t SendSystemControlCommand(const AVControlCommand& command) override;

    int32_t CastAudio(const SessionToken& token,
                      const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) override;

    int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId) override;

    int32_t Close(void) override;

    int32_t GetDistributedSessionControllers(const DistributedSessionType& sessionType,
        std::vector<std::shared_ptr<AVSessionController>>& sessionControllers) override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes) override;

    int32_t StopCastDiscovery() override;

    int32_t SetDiscoverable(const bool enable) override;

    int32_t StartDeviceLogging(int32_t fd, uint32_t maxSize) override;

    int32_t StopDeviceLogging() override;

    int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) override;

    int32_t StopCast(const SessionToken& sessionToken) override;
#endif

private:
    sptr<AVSessionServiceProxy> GetService();

    void RegisterServiceStateListener(sptr<ISystemAbilityManager> mgr);

    void OnServiceDie();

    void OnServiceStateChange(bool isAddSystemAbility);

    void RegisterClientDeathObserver();

    sptr<ISessionListener> GetSessionListenerClient(const std::shared_ptr<SessionListener>& listener);

    std::mutex lock_;
    sptr<AVSessionServiceProxy> service_;
    sptr<ServiceDeathRecipient> serviceDeathRecipient_;
    std::map<int32_t, sptr<ISessionListener>> listenerMapByUserId_;
    static sptr<ClientDeathStub> clientDeath_;
    DeathCallback deathCallback_;
    std::function<void()> serviceStartCallback_;
    sptr<ServiceStatusListener> serviceListener_ = nullptr;
    static constexpr int userIdForAllUsers_ = -1;
    std::atomic<bool> isServiceDie_ = false;
#ifdef START_STOP_ON_DEMAND_ENABLE
    const int32_t loadSystemAbilityWaitTimeOut_ = 30;
#endif
};

class ServiceStatusListener : public SystemAbilityStatusChangeStub {
public:
    explicit ServiceStatusListener(const std::function<void(bool)>& callback);

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    std::function<void(bool)> callback_;
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
