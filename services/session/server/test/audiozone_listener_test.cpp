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
#include <unistd.h>

#include "avsession_users_manager.h"
#include "avsession_service.h"
#include "session_listener_client.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

namespace {
    constexpr int32_t UID_TO_USER_ID_RATIO = 200000;
}

class MockSessionListener : public SessionListener {
public:
    MOCK_METHOD(void, OnSessionCreate, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnSessionRelease, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnTopSessionChange, (const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnSessionAddForAudioZone, (int32_t userId,
        const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnSessionRemoveForAudioZone, (int32_t userId,
        const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnTopSessionChangeForAudioZone, (int32_t userId,
        const AVSessionDescriptor& descriptor), (override));
    MOCK_METHOD(void, OnAudioSessionChecked, (const int32_t uid), (override));
    MOCK_METHOD(void, OnDeviceAvailable, (const OutputDeviceInfo& castOutputDeviceInfo), (override));
    MOCK_METHOD(void, OnDeviceOffline, (const std::string& deviceId), (override));
    MOCK_METHOD(void, OnRemoteDistributedSessionChange,
        (const std::vector<sptr<IRemoteObject>>& sessionControllers), (override));
    MOCK_METHOD(void, OnDeviceStateChange, (const DeviceState& deviceState), (override));
    MOCK_METHOD(void, OnActiveSessionChanged, (const std::vector<AVSessionDescriptor>& descriptors), (override));
    MOCK_METHOD(void, OnSystemCommonEvent, (const std::string& commonEvent, const std::string& args), (override));
};

class AudioZoneListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<MockSessionListener> mockListener_;
    std::shared_ptr<SessionListenerClient> listenerClient_;
    AVSessionDescriptor testDescriptor_;
};

void AudioZoneListenerTest::SetUpTestCase() {}

void AudioZoneListenerTest::TearDownTestCase() {}

void AudioZoneListenerTest::SetUp()
{
    mockListener_ = std::make_shared<MockSessionListener>();
    listenerClient_ = std::make_shared<SessionListenerClient>(mockListener_);
    
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    
    testDescriptor_.sessionId_ = "test_session_id";
    testDescriptor_.elementName_.SetBundleName("com.test.bundle");
    testDescriptor_.elementName_.SetAbilityName("TestAbility");
    testDescriptor_.pid_ = getpid();
    testDescriptor_.uid_ = getuid();
    testDescriptor_.userId_ = baseUserId;
}

void AudioZoneListenerTest::TearDown()
{
    mockListener_.reset();
    listenerClient_.reset();
}

/**
 * @tc.name: OnSessionAddForAudioZone_001
 * @tc.desc: Test OnSessionAddForAudioZone with valid userId and descriptor
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionAddForAudioZone_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(testDescriptor_.userId_, testing::_))
        .Times(1);
    
    int32_t userId = testDescriptor_.userId_;
    ErrCode result = listenerClient_->OnSessionAddForAudioZone(userId, testDescriptor_);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnSessionAddForAudioZone_002
 * @tc.desc: Test OnSessionAddForAudioZone with null listener
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionAddForAudioZone_002, TestSize.Level1)
{
    std::shared_ptr<SessionListenerClient> nullListenerClient = std::make_shared<SessionListenerClient>(nullptr);
    
    int32_t userId = testDescriptor_.userId_;
    ErrCode result = nullListenerClient->OnSessionAddForAudioZone(userId, testDescriptor_);
    EXPECT_EQ(result, AVSESSION_ERROR);
}

/**
 * @tc.name: OnSessionAddForAudioZone_003
 * @tc.desc: Test OnSessionAddForAudioZone with different userIds
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionAddForAudioZone_003, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1 = testDescriptor_;
    descriptor1.userId_ = userId1;
    descriptor1.uid_ = userId1 * 200000;
    
    AVSessionDescriptor descriptor2 = testDescriptor_;
    descriptor2.userId_ = userId2;
    descriptor2.uid_ = userId2 * 200000;
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionAddForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionAddForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnSessionRemoveForAudioZone_001
 * @tc.desc: Test OnSessionRemoveForAudioZone with valid userId and descriptor
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionRemoveForAudioZone_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(testDescriptor_.userId_, testing::_))
        .Times(1);
    
    int32_t userId = testDescriptor_.userId_;
    std::vector<AVSessionDescriptor> descriptors = {testDescriptor_};
    ErrCode result = listenerClient_->OnSessionRemoveForAudioZone(userId, descriptors);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnSessionRemoveForAudioZone_002
 * @tc.desc: Test OnSessionRemoveForAudioZone with null listener
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionRemoveForAudioZone_002, TestSize.Level1)
{
    std::shared_ptr<SessionListenerClient> nullListenerClient = std::make_shared<SessionListenerClient>(nullptr);
    
    int32_t userId = testDescriptor_.userId_;
    std::vector<AVSessionDescriptor> descriptors = {testDescriptor_};
    ErrCode result = nullListenerClient->OnSessionRemoveForAudioZone(userId, descriptors);
    EXPECT_EQ(result, AVSESSION_ERROR);
}

/**
 * @tc.name: OnSessionRemoveForAudioZone_003
 * @tc.desc: Test OnSessionRemoveForAudioZone with multiple userIds
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionRemoveForAudioZone_003, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1 = testDescriptor_;
    descriptor1.userId_ = userId1;
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    
    AVSessionDescriptor descriptor2 = testDescriptor_;
    descriptor2.userId_ = userId2;
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionRemoveForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionRemoveForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnTopSessionChangeForAudioZone_001
 * @tc.desc: Test OnTopSessionChangeForAudioZone with valid userId and descriptor
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnTopSessionChangeForAudioZone_001, TestSize.Level1)
{
    EXPECT_CALL(*mockListener_, OnTopSessionChangeForAudioZone(testDescriptor_.userId_, testing::_))
        .Times(1);
    
    int32_t userId = testDescriptor_.userId_;
    ErrCode result = listenerClient_->OnTopSessionChangeForAudioZone(userId, testDescriptor_);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnTopSessionChangeForAudioZone_002
 * @tc.desc: Test OnTopSessionChangeForAudioZone with null listener
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnTopSessionChangeForAudioZone_002, TestSize.Level1)
{
    std::shared_ptr<SessionListenerClient> nullListenerClient = std::make_shared<SessionListenerClient>(nullptr);
    
    int32_t userId = testDescriptor_.userId_;
    ErrCode result = nullListenerClient->OnTopSessionChangeForAudioZone(userId, testDescriptor_);
    EXPECT_EQ(result, AVSESSION_ERROR);
}

/**
 * @tc.name: OnTopSessionChangeForAudioZone_003
 * @tc.desc: Test OnTopSessionChangeForAudioZone with different userIds
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnTopSessionChangeForAudioZone_003, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1 = testDescriptor_;
    descriptor1.userId_ = userId1;
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    
    AVSessionDescriptor descriptor2 = testDescriptor_;
    descriptor2.userId_ = userId2;
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    
    EXPECT_CALL(*mockListener_, OnTopSessionChangeForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnTopSessionChangeForAudioZone(userId2, testing::_))
        .Times(1);
    
    ErrCode result1 = listenerClient_->OnTopSessionChangeForAudioZone(userId1, descriptor1);
    ErrCode result2 = listenerClient_->OnTopSessionChangeForAudioZone(userId2, descriptor2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: RegisterSessionListenerForUser_001
 * @tc.desc: Test RegisterSessionListenerForUser with valid userId
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, RegisterSessionListenerForUser_001, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t userId = testDescriptor_.userId_;
    int32_t result = usersManager.RegisterSessionListenerForUser(userId, listener);
    EXPECT_EQ(result, AVSESSION_SUCCESS);
}

/**
 * @tc.name: RegisterSessionListenerForUser_002
 * @tc.desc: Test RegisterSessionListenerForUser with different userIds
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, RegisterSessionListenerForUser_002, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    int32_t result1 = usersManager.RegisterSessionListenerForUser(userId1, listener);
    int32_t result2 = usersManager.RegisterSessionListenerForUser(userId2, listener);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: AudioZoneEventFlow_001
 * @tc.desc: Test complete AudioZone event flow: register -> create -> destroy
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneEventFlow_001, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t userId = testDescriptor_.userId_;
    pid_t pid = getpid() + 1000;
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(userId, testing::_))
        .Times(1);
    
    usersManager.AddSessionListenerForAudioZone(pid, listener, userId);
    
    std::vector<AVSessionDescriptor> descriptors = {testDescriptor_};
    ErrCode createResult = listenerClient_->OnSessionAddForAudioZone(userId, descriptors);
    ErrCode destroyResult = listenerClient_->OnSessionRemoveForAudioZone(userId, descriptors);
    
    EXPECT_EQ(createResult, AVSESSION_SUCCESS);
    EXPECT_EQ(destroyResult, AVSESSION_SUCCESS);
}

/**
 * @tc.name: AudioZoneMultipleUsers_001
 * @tc.desc: Test AudioZone with multiple users in same zone
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneMultipleUsers_001, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    pid_t pid1 = getpid() + 2000;
    pid_t pid2 = getpid() + 2001;
    
    AVSessionDescriptor descriptor1 = testDescriptor_;
    descriptor1.userId_ = userId1;
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    
    AVSessionDescriptor descriptor2 = testDescriptor_;
    descriptor2.userId_ = userId2;
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    
    usersManager.AddSessionListenerForAudioZone(pid1, listener, userId1);
    usersManager.AddSessionListenerForAudioZone(pid2, listener, userId2);
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionAddForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionAddForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnSessionAddForAudioZone_004
 * @tc.desc: Test OnSessionAddForAudioZone with different descriptors
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionAddForAudioZone_004, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1;
    descriptor1.sessionId_ = "session1";
    descriptor1.elementName_.SetBundleName("com.test.bundle1");
    descriptor1.pid_ = getpid();
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    descriptor1.userId_ = userId1;
    
    AVSessionDescriptor descriptor2;
    descriptor2.sessionId_ = "session2";
    descriptor2.elementName_.SetBundleName("com.test.bundle2");
    descriptor2.pid_ = getpid();
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    descriptor2.userId_ = userId2;
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionAddForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionAddForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnSessionRemoveForAudioZone_004
 * @tc.desc: Test OnSessionRemoveForAudioZone with different descriptors
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnSessionRemoveForAudioZone_004, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1;
    descriptor1.sessionId_ = "session1";
    descriptor1.elementName_.SetBundleName("com.test.bundle1");
    descriptor1.pid_ = getpid();
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    descriptor1.userId_ = userId1;
    
    AVSessionDescriptor descriptor2;
    descriptor2.sessionId_ = "session2";
    descriptor2.elementName_.SetBundleName("com.test.bundle2");
    descriptor2.pid_ = getpid();
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    descriptor2.userId_ = userId2;
    
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionRemoveForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionRemoveForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionRemoveForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnTopSessionChangeForAudioZone_004
 * @tc.desc: Test OnTopSessionChangeForAudioZone with different descriptors
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, OnTopSessionChangeForAudioZone_004, TestSize.Level1)
{
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 2;
    
    AVSessionDescriptor descriptor1;
    descriptor1.sessionId_ = "session1";
    descriptor1.elementName_.SetBundleName("com.test.bundle1");
    descriptor1.pid_ = getpid();
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    descriptor1.userId_ = userId1;
    
    AVSessionDescriptor descriptor2;
    descriptor2.sessionId_ = "session2";
    descriptor2.elementName_.SetBundleName("com.test.bundle2");
    descriptor2.pid_ = getpid();
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    descriptor2.userId_ = userId2;
    
    EXPECT_CALL(*mockListener_, OnTopSessionChangeForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnTopSessionChangeForAudioZone(userId2, testing::_))
        .Times(1);
    
    ErrCode result1 = listenerClient_->OnTopSessionChangeForAudioZone(userId1, descriptor1);
    ErrCode result2 = listenerClient_->OnTopSessionChangeForAudioZone(userId2, descriptor2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
}

/**
 * @tc.name: AudioZoneListenerConcurrent_001
 * @tc.desc: Test concurrent listener operations for same userId
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneListenerConcurrent_001, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t userId = testDescriptor_.userId_;
    pid_t pid1 = getpid() + 3000;
    pid_t pid2 = getpid() + 3001;
    
    usersManager.AddSessionListenerForAudioZone(pid1, listener, userId);
    usersManager.AddSessionListenerForAudioZone(pid2, listener, userId);
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId, testing::_))
        .Times(2);
    
    std::vector<AVSessionDescriptor> descriptors = {testDescriptor_};
    listenerClient_->OnSessionAddForAudioZone(userId, descriptors);
    listenerClient_->OnSessionAddForAudioZone(userId, descriptors);
    
    usersManager.RemoveSessionListenerForAudioZone(pid1);
    usersManager.RemoveSessionListenerForAudioZone(pid2);
}

/**
 * @tc.name: AudioZoneListenerNullCheck_001
 * @tc.desc: Test null listener handling in various scenarios
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneListenerNullCheck_001, TestSize.Level1)
{
    std::shared_ptr<MockSessionListener> nullMockListener;
    std::shared_ptr<SessionListenerClient> nullListenerClient =
        std::make_shared<SessionListenerClient>(nullMockListener);
    
    int32_t userId = testDescriptor_.userId_;
    std::vector<AVSessionDescriptor> descriptors = {testDescriptor_};
    
    ErrCode createResult = nullListenerClient->OnSessionAddForAudioZone(userId, descriptors);
    ErrCode destroyResult = nullListenerClient->OnSessionRemoveForAudioZone(userId, descriptors);
    ErrCode topResult = nullListenerClient->OnTopSessionChangeForAudioZone(userId, testDescriptor_);
    
    EXPECT_EQ(createResult, AVSESSION_ERROR);
    EXPECT_EQ(destroyResult, AVSESSION_ERROR);
    EXPECT_EQ(topResult, AVSESSION_ERROR);
}

/**
 * @tc.name: AudioZoneListenerDescriptorValidation_001
 * @tc.desc: Test with various descriptor values
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneListenerDescriptorValidation_001, TestSize.Level1)
{
    AVSessionDescriptor emptyDescriptor;
    emptyDescriptor.sessionId_ = "";
    emptyDescriptor.pid_ = getpid();
    emptyDescriptor.uid_ = getuid();
    emptyDescriptor.userId_ = 0;
    
    AVSessionDescriptor validDescriptor;
    validDescriptor.sessionId_ = "valid_session";
    validDescriptor.elementName_.SetBundleName("com.valid.bundle");
    validDescriptor.pid_ = getpid();
    int32_t userId = testDescriptor_.userId_;
    validDescriptor.uid_ = userId * UID_TO_USER_ID_RATIO;
    validDescriptor.userId_ = userId;
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(testing::_, testing::_))
        .Times(2);
    
    std::vector<AVSessionDescriptor> emptyDescriptors = {emptyDescriptor};
    std::vector<AVSessionDescriptor> validDescriptors = {validDescriptor};
    ErrCode emptyResult = listenerClient_->OnSessionAddForAudioZone(userId, emptyDescriptors);
    ErrCode validResult = listenerClient_->OnSessionAddForAudioZone(userId, validDescriptors);
    
    EXPECT_EQ(emptyResult, AVSESSION_SUCCESS);
    EXPECT_EQ(validResult, AVSESSION_SUCCESS);
}

/**
 * @tc.name: AudioZoneMultipleUsers_002
 * @tc.desc: Test AudioZone with users in different zones
 * @tc.type: FUNC
 * @tc.require: IssueNumber
 */
HWTEST_F(AudioZoneListenerTest, AudioZoneMultipleUsers_002, TestSize.Level1)
{
    auto& usersManager = AVSessionUsersManager::GetInstance();
    sptr<ISessionListener> listener = iface_cast<ISessionListener>(listenerClient_->AsObject());
    
    int32_t baseUserId = AVSessionUsersManager::GetInstance().GetCurrentUserId();
    int32_t userId1 = baseUserId + 1;
    int32_t userId2 = baseUserId + 100;
    pid_t pid1 = getpid() + 4000;
    pid_t pid2 = getpid() + 4001;
    
    AVSessionDescriptor descriptor1 = testDescriptor_;
    descriptor1.userId_ = userId1;
    descriptor1.uid_ = userId1 * UID_TO_USER_ID_RATIO;
    
    AVSessionDescriptor descriptor2 = testDescriptor_;
    descriptor2.userId_ = userId2;
    descriptor2.uid_ = userId2 * UID_TO_USER_ID_RATIO;
    
    usersManager.AddSessionListenerForAudioZone(pid1, listener, userId1);
    usersManager.AddSessionListenerForAudioZone(pid2, listener, userId2);
    
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId1, testing::_))
        .Times(1);
    EXPECT_CALL(*mockListener_, OnSessionAddForAudioZone(userId2, testing::_))
        .Times(1);
    
    std::vector<AVSessionDescriptor> descriptors1 = {descriptor1};
    std::vector<AVSessionDescriptor> descriptors2 = {descriptor2};
    ErrCode result1 = listenerClient_->OnSessionAddForAudioZone(userId1, descriptors1);
    ErrCode result2 = listenerClient_->OnSessionAddForAudioZone(userId2, descriptors2);
    
    EXPECT_EQ(result1, AVSESSION_SUCCESS);
    EXPECT_EQ(result2, AVSESSION_SUCCESS);
    
    usersManager.RemoveSessionListenerForAudioZone(pid1);
    usersManager.RemoveSessionListenerForAudioZone(pid2);
}

} // namespace AVSession
} // namespace OHOS