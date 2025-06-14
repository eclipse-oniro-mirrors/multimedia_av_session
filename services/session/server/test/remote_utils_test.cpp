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

#include <gtest/gtest.h>
#include "json_utils.h"
#include "avsession_log.h"
#include "av_session.h"
#include "avcontrol_command.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class RemoteUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RemoteUtilsTest::SetUpTestCase()
{}

void RemoteUtilsTest::TearDownTestCase()
{}

void RemoteUtilsTest::SetUp()
{}

void RemoteUtilsTest::TearDown()
{}

/**
* @tc.name: ConvertSessionType001
* @tc.desc: set sessionType_ as SESSION_TYPE_AUDIO
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(RemoteUtilsTest, ConvertSessionType001, TestSize.Level0)
{
    SLOGI("ConvertSessionType001 begin!");
    std::string sessionInfo;
    AVSessionDescriptor descriptor;
    AVSessionDescriptor descriptorOut;
    AVSessionBasicInfo basicInfo;
    descriptor.sessionId_ = "123";
    descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
    descriptor.elementName_.SetBundleName("test.ohos.avsession");
    descriptor.elementName_.SetAbilityName("test.ability");
    descriptor.sessionTag_ = "tag";
    descriptor.isThirdPartyApp_ = false;
    EXPECT_EQ(JsonUtils::SetSessionBasicInfo(sessionInfo, basicInfo), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::SetSessionDescriptor(sessionInfo, descriptor), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::GetSessionDescriptor(sessionInfo, descriptorOut), AVSESSION_SUCCESS);
    SLOGI("ConvertSessionType001 end!");
}

/**
* @tc.name: ConvertSessionType002
* @tc.desc: set sessionType_ as SESSION_TYPE_VIDEO
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(RemoteUtilsTest, ConvertSessionType002, TestSize.Level0)
{
    SLOGI("ConvertSessionType002 begin!");
    std::string sessionInfo;
    AVSessionDescriptor descriptor;
    AVSessionDescriptor descriptorOut;
    AVSessionBasicInfo basicInfo;
    descriptor.sessionId_ = "123";
    descriptor.sessionType_ = AVSession::SESSION_TYPE_VIDEO;
    descriptor.elementName_.SetBundleName("test.ohos.avsession");
    descriptor.elementName_.SetAbilityName("test.ability");
    descriptor.sessionTag_ = "tag";
    descriptor.isThirdPartyApp_ = false;
    EXPECT_EQ(JsonUtils::SetSessionBasicInfo(sessionInfo, basicInfo), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::SetSessionDescriptor(sessionInfo, descriptor), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::GetSessionDescriptor(sessionInfo, descriptorOut), AVSESSION_SUCCESS);
    SLOGI("ConvertSessionType002 end!");
}

/**
* @tc.name: ConvertSessionType003
* @tc.desc: set sessionType_ as SESSION_TYPE_INVALID
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(RemoteUtilsTest, ConvertSessionType003, TestSize.Level0)
{
    SLOGI("ConvertSessionType003 begin!");
    std::string sessionInfo;
    AVSessionDescriptor descriptor;
    AVSessionDescriptor descriptorOut;
    AVSessionBasicInfo basicInfo;
    descriptor.sessionId_ = "123";
    descriptor.sessionType_ = AVSession::SESSION_TYPE_INVALID;
    descriptor.elementName_.SetBundleName("test.ohos.avsession");
    descriptor.elementName_.SetAbilityName("test.ability");
    descriptor.sessionTag_ = "tag";
    descriptor.isThirdPartyApp_ = false;
    EXPECT_EQ(JsonUtils::SetSessionBasicInfo(sessionInfo, basicInfo), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::SetSessionDescriptor(sessionInfo, descriptor), AVSESSION_SUCCESS);
    EXPECT_EQ(JsonUtils::GetSessionDescriptor(sessionInfo, descriptorOut), AVSESSION_SUCCESS);
    SLOGI("ConvertSessionType003 end!");
}

/**
* @tc.name: GetJsonCapability001
* @tc.desc: get metaData or playbackState or controlCommand capability
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(RemoteUtilsTest, GetJsonCapability001, TestSize.Level0)
{
    SLOGI("GetJsonCapability001 begin!");
    std::vector<std::vector<int32_t>> localCapability(4);
    localCapability[SESSION_DATA_META] = AVMetaData::localCapability;
    localCapability[SESSION_DATA_PLAYBACK_STATE] = AVPlaybackState::localCapability;
    localCapability[SESSION_DATA_CONTROL_COMMAND] = AVControlCommand::localCapability;
    std::string jsonSinkCap;
    EXPECT_EQ(JsonUtils::GetJsonCapability(localCapability, jsonSinkCap), AVSESSION_SUCCESS);
    SLOGI("GetJsonCapability001 end!");
}