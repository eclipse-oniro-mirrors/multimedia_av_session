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
#include "avsession_dumper.h"
#include "avsession_proxy.h"
#include "av_session.h"

using namespace testing::ext;
// using namespace OHOS;
// using namespace OHOS::AVSession;
namespace OHOS::AVSession {

static const std::string ARGS_HELP = "-h";
static const std::string ILLEGAL_INFORMATION = "AVSession service, enter '-h' for usage.\n";
static const std::string ARGS_SHOW_METADATA = "-show_metadata";
static const std::string ARGS_SHOW_SESSION_INFO = "-show_session_info";
static const std::string ARGS_SHOW_CONTROLLER_INFO = "-show_controller_info";
static const std::string ARGS_SHOW_ERROR_INFO = "-show_error_info";
static const std::string ARGS_TRUSTED_DEVICES_INFO = "-show_trusted_devices_Info";

std::shared_ptr<AVSessionDumper> g_AVSessionDumper = nullptr;
sptr<AVSessionService> g_AVSessionService = nullptr;
class AVSessionDumperAnotherTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionDumperAnotherTest::SetUpTestCase()
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    g_AVSessionService = new AVSessionService(systemAbilityId, runOnCreate);
    g_AVSessionService->OnStart();
    ASSERT_NE(g_AVSessionService, nullptr);
    
    g_AVSessionDumper = std::make_shared<AVSessionDumper>();
    ASSERT_NE(g_AVSessionDumper, nullptr);
}

void AVSessionDumperAnotherTest::TearDownTestCase()
{
    g_AVSessionService->OnStop();
}

void AVSessionDumperAnotherTest::SetUp()

{
}

void AVSessionDumperAnotherTest::TearDown()
{
}

/**
 * @tc.name: Dump__ShowIllegalInfo001
 * @tc.desc: Test ShowIllegalInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowIllegalInfo001, TestSize.Level1)
{
    SLOGI("Dump__ShowHelp001 begin!");
    std::vector<std::string> args = { "aa", "bb" };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_EQ(result, ILLEGAL_INFORMATION);
    SLOGI("Dump__ShowHelp001 end!");
}

/**
 * @tc.name: Dump__ShowIllegalInfo002
 * @tc.desc: Test ShowIllegalInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowIllegalInfo002, TestSize.Level1)
{
    SLOGI("Dump__ShowHelp002 begin!");
    std::vector<std::string> args = { "****" };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_EQ(result, ILLEGAL_INFORMATION);
    SLOGI("Dump__ShowHelp002 end!");
}

/**
 * @tc.name: Dump__ShowHelp
 * @tc.desc: Test ShowHelp
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowHelp, TestSize.Level1)
{
    SLOGI("Dump__ShowHelp begin!");

    std::vector<std::string> args = { ARGS_HELP };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);

    SLOGI("Dump__ShowHelp end!");
}

/**
 * @tc.name: Dump__ShowMetaData
 * @tc.desc: Test ShowMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowMetaData, TestSize.Level1)
{
    SLOGI("Dump__ShowMetaData begin!");

    std::vector<std::string> args = { ARGS_SHOW_METADATA };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_EQ(result.size(), 0);

    SLOGI("Dump__ShowMetaData end!");
}

/**
 * @tc.name: Dump__ShowSessionInfo__SESSION_TYPE_AUDIO
 * @tc.desc: Test ShowSessionInfo by SESSION_TYPE_AUDIO
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_AUDIO, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_AUDIO begin!");
    std::vector<std::string> args = { ARGS_SHOW_SESSION_INFO };
    std::string result = "";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto obj = g_AVSessionService->CreateSessionInner("test", AVSession::SESSION_TYPE_AUDIO, elementName);
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_AUDIO end!");
}

/**
 * @tc.name: Dump__ShowSessionInfo__SESSION_TYPE_VIDEO
 * @tc.desc: Test ShowSessionInfo by SESSION_TYPE_VIDEO
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VIDEO, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO begin!");

    std::vector<std::string> args = { ARGS_SHOW_SESSION_INFO };
    std::string result = "";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto obj = g_AVSessionService->CreateSessionInner("test", AVSession::SESSION_TYPE_VIDEO, elementName);
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO end!");
}

/**
 * @tc.name: Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL
 * @tc.desc: Test ShowSessionInfo by SESSION_TYPE_VOICE_CALL
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL begin!");
    std::vector<std::string> args = { ARGS_SHOW_SESSION_INFO };
    std::string result = "";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto obj = g_AVSessionService->CreateSessionInner("test", AVSession::SESSION_TYPE_VOICE_CALL, elementName);
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL end!");
}

/**
 * @tc.name: Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL
 * @tc.desc: Test ShowSessionInfo by SESSION_TYPE_VIDEO_CALL
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL begin!");
    std::vector<std::string> args = { ARGS_SHOW_SESSION_INFO };
    std::string result = "";
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    auto obj = g_AVSessionService->CreateSessionInner("test", AVSession::SESSION_TYPE_VIDEO_CALL, elementName);
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL end!");
}

/**
 * @tc.name: Dump__ShowControllerInfo
 * @tc.desc: Test ShowControllerInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowControllerInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowControllerInfo begin!");
    std::vector<std::string> args = { ARGS_SHOW_CONTROLLER_INFO };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowControllerInfo end!");
}

/**
 * @tc.name: Dump__ShowErrorInfo001
 * @tc.desc: Test ShowErrorInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowErrorInfo001, TestSize.Level1)
{
    SLOGI("Dump__ShowErrorInfo001 begin!");
    std::vector<std::string> args = { ARGS_SHOW_ERROR_INFO };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowErrorInfo001 end!");
}

/**
 * @tc.name: Dump__ShowErrorInfo002
 * @tc.desc: Test ShowErrorInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowErrorInfo002, TestSize.Level1)
{
    SLOGI("Dump__ShowErrorInfo002 begin!");
    std::vector<std::string> args = { ARGS_SHOW_ERROR_INFO };
    std::string result = "";
    g_AVSessionDumper->SetErrorInfo("***");
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowErrorInfo002 end!");
}

/**
 * @tc.name: Dump__ShowTrustedDevicesInfo
 * @tc.desc: Test ShowTrustedDevicesInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowTrustedDevicesInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowTrustedDevicesInfo begin!");
    std::vector<std::string> args = { ARGS_TRUSTED_DEVICES_INFO };
    std::string result = "";
    g_AVSessionDumper->Dump(args, result, *g_AVSessionService);
    EXPECT_NE(result.size(), 0);
    SLOGI("Dump__ShowTrustedDevicesInfo end!");
}

}