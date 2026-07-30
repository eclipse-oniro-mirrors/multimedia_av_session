/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avsession_log.h"

#define private public
#include "avsession_manager_impl.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVSessionManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionManagerImplTest::SetUpTestCase()
{}

void AVSessionManagerImplTest::TearDownTestCase()
{}

void AVSessionManagerImplTest::SetUp()
{}

void AVSessionManagerImplTest::TearDown()
{}

/**
* @tc.name: OnPlaybackStateChange001
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange001, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    std::shared_ptr<AVSession> ptr = impl.CreateSession("", 0, elementName);
    EXPECT_EQ(ptr, nullptr);
}

/**
* @tc.name: OnPlaybackStateChange002
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange002, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    std::shared_ptr<AVSession> ptr = impl.CreateSession("xiaoming", 0, elementName);
    EXPECT_EQ(ptr, nullptr);
}

/**
* @tc.name: OnPlaybackStateChange003
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange003, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    std::shared_ptr<AVSession> ptr = impl.CreateSession("", 0, elementName);
    EXPECT_EQ(ptr, nullptr);
}

/**
* @tc.name: OnPlaybackStateChange004
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange004, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    std::shared_ptr<AVSession> ptr = impl.CreateSession("xiaoming", 0, elementName);
    EXPECT_EQ(ptr, nullptr);
}

/**
* @tc.name: OnPlaybackStateChange005
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange005, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("", 0, elementName, session);
    EXPECT_EQ(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange006
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange006, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", 0, elementName, session);
    EXPECT_EQ(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange007
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange007, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", 0, elementName, session);
    EXPECT_EQ(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange008
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange008, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", AVSession::SESSION_TYPE_INVALID, elementName, session);
    EXPECT_EQ(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange009
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange009, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", AVSession::SESSION_TYPE_AUDIO, elementName, session);
    EXPECT_NE(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange010
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange010, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", AVSession::SESSION_TYPE_VIDEO, elementName, session);
    EXPECT_NE(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange011
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange011, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", AVSession::SESSION_TYPE_VOICE_CALL, elementName, session);
    EXPECT_NE(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: OnPlaybackStateChange012
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnPlaybackStateChange012, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("xiaoming");
    elementName.SetAbilityName("xiaoqiang");
    std::shared_ptr<AVSession> session = nullptr;
    int32_t result = impl.CreateSession("xiaoming", AVSession::SESSION_TYPE_VIDEO_CALL, elementName, session);
    EXPECT_NE(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: CreateController001
* @tc.desc: test CreateController
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, CreateController001, TestSize.Level0)
{
    AVSessionManagerImpl impl;
    std::shared_ptr<AVSessionController> controller = nullptr;
    int32_t result = impl.CreateController("", controller);
    EXPECT_EQ(result, ERR_INVALID_PARAM);
}

/**
* @tc.name: GetDistributedSessionControllers001
* @tc.desc: test GetDistributedSessionControllers
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, GetDistributedSessionControllers001, TestSize.Level1)
{
    AVSessionManagerImpl impl;
    std::vector<std::shared_ptr<AVSessionController>> controllers;
    int32_t result =
	     impl.GetDistributedSessionControllers(DistributedSessionType::TYPE_SESSION_REMOTE, controllers);
    EXPECT_EQ(result, ERR_REMOTE_CONNECTION_NOT_EXIST);
}

/**
* @tc.name: GetDistributedSessionControllers002
* @tc.desc: test GetDistributedSessionControllers
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, GetDistributedSessionControllers002, TestSize.Level1)
{
    AVSessionManagerImpl impl;
    std::vector<std::shared_ptr<AVSessionController>> controllers;
    int32_t result =
	    impl.GetDistributedSessionControllers(DistributedSessionType::TYPE_SESSION_MIGRATE_IN, controllers);
    EXPECT_EQ(result, ERR_REMOTE_CONNECTION_NOT_EXIST);
}

/**
* @tc.name: GetDistributedSessionControllers003
* @tc.desc: test GetDistributedSessionControllers
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, GetDistributedSessionControllers003, TestSize.Level1)
{
    AVSessionManagerImpl impl;
    std::vector<std::shared_ptr<AVSessionController>> controllers;
    int32_t result =
	    impl.GetDistributedSessionControllers(DistributedSessionType::TYPE_SESSION_MIGRATE_OUT, controllers);
    EXPECT_EQ(result, ERR_REMOTE_CONNECTION_NOT_EXIST);
}

/**
* @tc.name: RegisterServiceStartCallbackInvoke001
* @tc.desc: test RegisterServiceStartCallback, callback is invoked on service restart
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, RegisterServiceStartCallbackInvoke001, TestSize.Level1)
{
    SLOGI("RegisterServiceStartCallbackInvoke001 begin");
    AVSessionManagerImpl impl;
    bool isCallbackInvoked = false;
    int32_t ret = impl.RegisterServiceStartCallback([&isCallbackInvoked]() {
        isCallbackInvoked = true;
    });
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    impl.isServiceDie_ = true;
    impl.OnServiceStateChange(true);
    EXPECT_TRUE(isCallbackInvoked);
    EXPECT_FALSE(impl.isServiceDie_.load());
    SLOGI("RegisterServiceStartCallbackInvoke001 end");
}

/**
* @tc.name: UnregisterServiceStartCallbackNoInvoke001
* @tc.desc: test UnregisterServiceStartCallback, callback is not invoked after unregister
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, UnregisterServiceStartCallbackNoInvoke001, TestSize.Level1)
{
    SLOGI("UnregisterServiceStartCallbackNoInvoke001 begin");
    AVSessionManagerImpl impl;
    bool isCallbackInvoked = false;
    int32_t ret = impl.RegisterServiceStartCallback([&isCallbackInvoked]() {
        isCallbackInvoked = true;
    });
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ret = impl.UnregisterServiceStartCallback();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    impl.isServiceDie_ = true;
    impl.OnServiceStateChange(true);
    EXPECT_FALSE(isCallbackInvoked);
    EXPECT_TRUE(impl.isServiceDie_.load());
    SLOGI("UnregisterServiceStartCallbackNoInvoke001 end");
}

/**
* @tc.name: OnServiceStateChangeSetServiceDie001
* @tc.desc: test OnServiceStateChange remove then add, callback invoked once service die
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVSessionManagerImplTest, OnServiceStateChangeSetServiceDie001, TestSize.Level1)
{
    SLOGI("OnServiceStateChangeSetServiceDie001 begin");
    AVSessionManagerImpl impl;
    bool isCallbackInvoked = false;
    int32_t ret = impl.RegisterServiceStartCallback([&isCallbackInvoked]() {
        isCallbackInvoked = true;
    });
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    impl.OnServiceStateChange(false);
    EXPECT_FALSE(isCallbackInvoked);
    EXPECT_TRUE(impl.isServiceDie_.load());
    impl.OnServiceStateChange(true);
    EXPECT_TRUE(isCallbackInvoked);
    EXPECT_FALSE(impl.isServiceDie_.load());
    SLOGI("OnServiceStateChangeSetServiceDie001 end");
}
} // namespace AVSession
} // namespace OHOS