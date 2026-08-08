/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <chrono>
#include <string>
#include <vector>

#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "element_name.h"
#include "system_ability_definition.h"

#define private public
#define protected public
#include "avsession_service.h"
#include "avsession_item.h"
#include "avsession_users_manager.h"
#include "session_listener_client.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AVSession {

class MockSessionListener : public SessionListener {
public:
    MOCK_METHOD(void, OnSessionCreate, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnSessionRelease, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnTopSessionChange, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, SessionAddForAudioZone, 
        (int32_t userId, const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, SessionRemoveForAudioZone, 
        (int32_t userId, const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, SessionTopChangeForAudioZone, 
        (int32_t userId, const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnAudioSessionChecked, (const int32_t uid), (override));
    MOCK_METHOD(void, OnDeviceAvailable, (const OutputDeviceInfo& castOutputDeviceInfo), (override));
    MOCK_METHOD(void, OnDeviceOffline, (const std::string& deviceId), (override));
    MOCK_METHOD(void, OnRemoteDistributedSessionChange,
        (const std::vector<sptr<IRemoteObject>>& sessionControllers), (override));
    MOCK_METHOD(void, OnDeviceStateChange, (const DeviceState& deviceState), (override));
    MOCK_METHOD(void, OnActiveSessionChanged, (const std::vector<AVSessionDescriptor>& descriptors), (override));
    MOCK_METHOD(void, OnSystemCommonEvent, (const std::string& commonEvent, const std::string& args), (override));
    
    sptr<IRemoteObject> AsObject() override { return nullptr; }
};

class AVSessionAudioZoneIntegrationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    sptr<AVSessionItem> CreateSessionForUser(int32_t userId, const std::string& tag);
    void SetZoneMapping(int32_t zoneId, const std::vector<int32_t>& userIds);
    void SimulateZoneChange(int32_t userId, int32_t oldZoneId, int32_t newZoneId);
    void SetSessionPlaying(sptr<AVSessionItem> session);
    
    AVSessionService* service_ = nullptr;
    std::shared_ptr<MockSessionListener> mockListener100_;
    std::shared_ptr<MockSessionListener> mockListener101_;
    std::shared_ptr<MockSessionListener> mockListener102_;
    std::shared_ptr<SessionListenerClient> listenerClient100_;
    std::shared_ptr<SessionListenerClient> listenerClient101_;
    std::shared_ptr<SessionListenerClient> listenerClient102_;
    
    static constexpr int32_t USER_ID_100 = 100;
    static constexpr int32_t USER_ID_101 = 101;
    static constexpr int32_t USER_ID_102 = 102;
    static constexpr int32_t ZONE_ID_1 = 1;
    static constexpr int32_t ZONE_ID_2 = 2;
};

void AVSessionAudioZoneIntegrationTest::SetUpTestCase()
{
    SLOGI("AVSessionAudioZoneIntegrationTest SetUpTestCase");
}

void AVSessionAudioZoneIntegrationTest::TearDownTestCase()
{
    SLOGI("AVSessionAudioZoneIntegrationTest TearDownTestCase");
}

void AVSessionAudioZoneIntegrationTest::SetUp()
{
    SLOGI("AVSessionAudioZoneIntegrationTest SetUp");
    
    service_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    ASSERT_TRUE(service_ != nullptr);
    
    mockListener100_ = std::make_shared<MockSessionListener>();
    mockListener101_ = std::make_shared<MockSessionListener>();
    mockListener102_ = std::make_shared<MockSessionListener>();
    
    listenerClient100_ = std::make_shared<SessionListenerClient>(mockListener100_);
    listenerClient101_ = std::make_shared<SessionListenerClient>(mockListener101_);
    listenerClient102_ = std::make_shared<SessionListenerClient>(mockListener102_);
    
    pid_t pid = getpid();
    service_->GetUsersManager().AddSessionListenerForUser(pid,
        iface_cast<ISessionListener>(listenerClient100_->AsObject()), USER_ID_100);
    service_->GetUsersManager().AddSessionListenerForUser(pid + 1,
        iface_cast<ISessionListener>(listenerClient101_->AsObject()), USER_ID_101);
    service_->GetUsersManager().AddSessionListenerForUser(pid + 2,
        iface_cast<ISessionListener>(listenerClient102_->AsObject()), USER_ID_102);
}

void AVSessionAudioZoneIntegrationTest::TearDown()
{
    SLOGI("AVSessionAudioZoneIntegrationTest TearDown");
    
    mockListener100_.reset();
    mockListener101_.reset();
    mockListener102_.reset();
    listenerClient100_.reset();
    listenerClient101_.reset();
    listenerClient102_.reset();
    
    if (service_ != nullptr) {
        delete service_;
        service_ = nullptr;
    }
}

sptr<AVSessionItem> AVSessionAudioZoneIntegrationTest::CreateSessionForUser(
    int32_t userId, const std::string& tag)
{
    ElementName elementName;
    elementName.SetBundleName("com.test." + tag);
    elementName.SetAbilityName("Ability_" + tag);
    
    auto session = service_->CreateSessionInner(tag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    if (session != nullptr) {
        session->descriptor_.userId_ = userId;
    }
    
    SLOGI("Created session %{public}s for user %{public}d", tag.c_str(), userId);
    return session;
}

void AVSessionAudioZoneIntegrationTest::SetZoneMapping(int32_t zoneId, const std::vector<int32_t>& userIds)
{
    auto& zoneToUserid = service_->GetUsersManager().zoneToUserid_;
    zoneToUserid[zoneId] = userIds;
    
    SLOGI("Set zone mapping: zone %{public}d -> users size=%{public}zu", zoneId, userIds.size());
}

void AVSessionAudioZoneIntegrationTest::SimulateZoneChange(
    int32_t userId, int32_t oldZoneId, int32_t newZoneId)
{
    auto& zoneToUserid = service_->GetUsersManager().zoneToUserid_;
    
    if (zoneToUserid.find(oldZoneId) != zoneToUserid.end()) {
        auto& oldUsers = zoneToUserid[oldZoneId];
        oldUsers.erase(std::remove(oldUsers.begin(), oldUsers.end(), userId), oldUsers.end());
        if (oldUsers.empty()) {
            zoneToUserid.erase(oldZoneId);
        }
    }
    
    if (zoneToUserid.find(newZoneId) == zoneToUserid.end()) {
        zoneToUserid[newZoneId] = {};
    }
    zoneToUserid[newZoneId].push_back(userId);
    
    service_->HandleSessionStackChangeForAudioZone();
    
    SLOGI("Simulated zone change: user %{public}d from zone %{public}d to %{public}d",
        userId, oldZoneId, newZoneId);
}

void AVSessionAudioZoneIntegrationTest::SetSessionPlaying(sptr<AVSessionItem> session)
{
    if (session == nullptr) {
        return;
    }
    
    AVPlaybackState playbackState;
    playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    session->SetAVPlaybackState(playbackState);
    
    auto now = std::chrono::system_clock::now();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    session->SetPlayingTime(milliseconds);
    
    SLOGI("Set session %{public}s playing", session->GetSessionId().c_str());
}

/**
 * @tc.name: AudioZone_ZoneMappingInitialization_001
 * @tc.desc: Test zone mapping initialization and basic operations
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_ZoneMappingInitialization_001, TestSize.Level1)
{
    SLOGI("AudioZone_ZoneMappingInitialization_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101, USER_ID_102});
    SetZoneMapping(ZONE_ID_2, {200});
    
    auto users = service_->GetUsersManager().GetUsersInSameAudioZone(USER_ID_100);
    
    EXPECT_EQ(users.size(), 3);
    EXPECT_NE(std::find(users.begin(), users.end(), USER_ID_100), users.end());
    EXPECT_NE(std::find(users.begin(), users.end(), USER_ID_101), users.end());
    EXPECT_NE(std::find(users.begin(), users.end(), USER_ID_102), users.end());
    
    auto users2 = service_->GetUsersManager().GetUsersInSameAudioZone(200);
    EXPECT_EQ(users2.size(), 1);
    
    SLOGI("AudioZone_ZoneMappingInitialization_001 end!");
}

/**
 * @tc.name: AudioZone_SessionCreationWithBatchNotification_001
 * @tc.desc: Test session creation triggers batch notification to all users in same zone
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_SessionCreationWithBatchNotification_001, TestSize.Level1)
{
    SLOGI("AudioZone_SessionCreationWithBatchNotification_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101, USER_ID_102});
    
    auto sessionA = CreateSessionForUser(USER_ID_100, "sessionA");
    ASSERT_TRUE(sessionA != nullptr);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    
    using testing::_;
    using testing::Field;
    
    EXPECT_CALL(*mockListener100_, SessionAddForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionAddForAudioZone(USER_ID_101, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    service_->HandleSessionRelease(sessionA->GetSessionId());
    sessionA->Destroy();
    
    SLOGI("AudioZone_SessionCreationWithBatchNotification_001 end!");
}

/**
 * @tc.name: AudioZone_SessionPlaybackTopChange_001
 * @tc.desc: Test session playback triggers top session change notification
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_SessionPlaybackTopChange_001, TestSize.Level1)
{
    SLOGI("AudioZone_SessionPlaybackTopChange_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101, USER_ID_102});
    
    auto sessionA = CreateSessionForUser(USER_ID_100, "sessionA");
    auto sessionB = CreateSessionForUser(USER_ID_100, "sessionB");
    ASSERT_TRUE(sessionA != nullptr);
    ASSERT_TRUE(sessionB != nullptr);
    
    SetSessionPlaying(sessionA);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    
    using testing::_;
    using testing::Field;
    
    EXPECT_CALL(*mockListener100_, SessionTopChangeForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionTopChangeForAudioZone(USER_ID_101, _))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionTopChangeForAudioZone(USER_ID_102, _))
        .Times(1);
    
    service_->HandleSessionRelease(sessionA->GetSessionId());
    service_->HandleSessionRelease(sessionB->GetSessionId());
    sessionA->Destroy();
    sessionB->Destroy();
    
    SLOGI("AudioZone_SessionPlaybackTopChange_001 end!");
}

/**
 * @tc.name: AudioZone_ZoneSplitNotification_001
 * @tc.desc: Test user leaving zone triggers SessionRemoveForAudioZone notification
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_ZoneSplitNotification_001, TestSize.Level1)
{
    SLOGI("AudioZone_ZoneSplitNotification_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101, USER_ID_102});
    
    auto sessionA = CreateSessionForUser(USER_ID_100, "sessionA");
    auto sessionB = CreateSessionForUser(USER_ID_100, "sessionB");
    ASSERT_TRUE(sessionA != nullptr);
    ASSERT_TRUE(sessionB != nullptr);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    
    SimulateZoneChange(USER_ID_102, ZONE_ID_1, ZONE_ID_2);
    
    using testing::_;
    using testing::Field;
    
    // User 102 receives two remove notifications (sessionA and sessionB)
    EXPECT_CALL(*mockListener102_, SessionRemoveForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionRemoveForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    service_->HandleSessionRelease(sessionA->GetSessionId());
    service_->HandleSessionRelease(sessionB->GetSessionId());
    sessionA->Destroy();
    sessionB->Destroy();
    
    SLOGI("AudioZone_ZoneSplitNotification_001 end!");
}

/**
 * @tc.name: AudioZone_ZoneMergeNotification_001
 * @tc.desc: Test user joining zone triggers SessionAddForAudioZone notification
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_ZoneMergeNotification_001, TestSize.Level1)
{
    SLOGI("AudioZone_ZoneMergeNotification_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101});
    SetZoneMapping(ZONE_ID_2, {USER_ID_102});
    
    auto sessionA = CreateSessionForUser(USER_ID_100, "sessionA");
    auto sessionB = CreateSessionForUser(USER_ID_100, "sessionB");
    auto sessionC = CreateSessionForUser(USER_ID_102, "sessionC");
    ASSERT_TRUE(sessionA != nullptr);
    ASSERT_TRUE(sessionB != nullptr);
    ASSERT_TRUE(sessionC != nullptr);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_102);
    
    SimulateZoneChange(USER_ID_102, ZONE_ID_2, ZONE_ID_1);
    
    using testing::_;
    using testing::Field;
    
    // Users 100, 101 receive sessionC
    EXPECT_CALL(*mockListener100_, SessionAddForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionC->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionAddForAudioZone(USER_ID_101, 
        Field(&AVSessionDescriptor::sessionId_, sessionC->GetSessionId())))
        .Times(1);
    
    // User 102 receives sessionA and sessionB (two notifications)
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    service_->HandleSessionRelease(sessionA->GetSessionId());
    service_->HandleSessionRelease(sessionB->GetSessionId());
    service_->HandleSessionRelease(sessionC->GetSessionId());
    sessionA->Destroy();
    sessionB->Destroy();
    sessionC->Destroy();
    
    SLOGI("AudioZone_ZoneMergeNotification_001 end!");
}

/**
 * @tc.name: AudioZone_CompleteSessionLifecycle_001
 * @tc.desc: Test complete session lifecycle with zone changes
 *           Scenario: 
 *           1. 100,101,102 in zone 1
 *           2. 100 creates sessionA,B → batch notification
 *           3. sessionA plays → top change notification
 *           4. 102 moves to zone 2 → remove notification
 *           5. 102 creates sessionC → independent zone notification
 *           6. 102 rejoins zone 1 → merge notification
 * @tc.type: FUNC
 * @tc.require: Audio Zone Feature
 */
HWTEST_F(AVSessionAudioZoneIntegrationTest, AudioZone_CompleteSessionLifecycle_001, TestSize.Level1)
{
    SLOGI("AudioZone_CompleteSessionLifecycle_001 begin!");
    ASSERT_TRUE(service_ != nullptr);
    
    using testing::_;
    using testing::Field;
    
    SLOGI("Phase 1: Initial zone mapping");
    SetZoneMapping(ZONE_ID_1, {USER_ID_100, USER_ID_101, USER_ID_102});
    
    SLOGI("Phase 2: Create sessionA and sessionB for user 100");
    auto sessionA = CreateSessionForUser(USER_ID_100, "sessionA");
    auto sessionB = CreateSessionForUser(USER_ID_100, "sessionB");
    ASSERT_TRUE(sessionA != nullptr);
    ASSERT_TRUE(sessionB != nullptr);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    
    // Each user receives two notifications (sessionA and sessionB)
    EXPECT_CALL(*mockListener100_, SessionAddForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    EXPECT_CALL(*mockListener100_, SessionAddForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionAddForAudioZone(USER_ID_101, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    EXPECT_CALL(*mockListener101_, SessionAddForAudioZone(USER_ID_101, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    SLOGI("Phase 3: SessionA starts playing");
    SetSessionPlaying(sessionA);
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_100);
    
    EXPECT_CALL(*mockListener100_, SessionTopChangeForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionTopChangeForAudioZone(USER_ID_101, _))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionTopChangeForAudioZone(USER_ID_102, _))
        .Times(1);
    
    SLOGI("Phase 4: User 102 moves to zone 2 (bluetooth headset on)");
    SimulateZoneChange(USER_ID_102, ZONE_ID_1, ZONE_ID_2);
    
    // User 102 receives two remove notifications
    EXPECT_CALL(*mockListener102_, SessionRemoveForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    EXPECT_CALL(*mockListener102_, SessionRemoveForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    SLOGI("Phase 5: User 102 creates sessionC in zone 2");
    auto sessionC = CreateSessionForUser(USER_ID_102, "sessionC");
    ASSERT_TRUE(sessionC != nullptr);
    
    service_->GetUsersManager().UpdateAudioZoneInfoForUser(USER_ID_102);
    
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionC->GetSessionId())))
        .Times(1);
    
    SLOGI("Phase 6: User 102 rejoins zone 1 (bluetooth headset off)");
    SimulateZoneChange(USER_ID_102, ZONE_ID_2, ZONE_ID_1);
    
    // Users 100, 101 receive sessionC
    EXPECT_CALL(*mockListener100_, SessionAddForAudioZone(USER_ID_100, 
        Field(&AVSessionDescriptor::sessionId_, sessionC->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener101_, SessionAddForAudioZone(USER_ID_101, 
        Field(&AVSessionDescriptor::sessionId_, sessionC->GetSessionId())))
        .Times(1);
    
    // User 102 receives sessionA and sessionB (two notifications)
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionA->GetSessionId())))
        .Times(1);
    
    EXPECT_CALL(*mockListener102_, SessionAddForAudioZone(USER_ID_102, 
        Field(&AVSessionDescriptor::sessionId_, sessionB->GetSessionId())))
        .Times(1);
    
    SLOGI("Cleanup: Destroy sessions");
    service_->HandleSessionRelease(sessionA->GetSessionId());
    service_->HandleSessionRelease(sessionB->GetSessionId());
    service_->HandleSessionRelease(sessionC->GetSessionId());
    
    sessionA->Destroy();
    sessionB->Destroy();
    sessionC->Destroy();
    
    SLOGI("AudioZone_CompleteSessionLifecycle_001 end!");
}

} // namespace AVSession
} // namespace OHOS