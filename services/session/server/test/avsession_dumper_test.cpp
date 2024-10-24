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

#include "avsession_log.h"
#include "avsession_dumper.h"
#include "avsession_proxy.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AVSession;

static const std::string ARGS_HELP = "-h";
static const std::string ILLEGAL_INFORMATION = "AVSession service, enter '-h' for usage.\n";
static const std::string ARGS_SHOW_METADATA = "-show_metadata";
static const std::string ARGS_SHOW_SESSION_INFO = "-show_session_info";
static const std::string ARGS_SHOW_CONTROLLER_INFO = "-show_controller_info";
static const std::string ARGS_SHOW_ERROR_INFO = "-show_error_info";
static const std::string ARGS_TRUSTED_DEVICES_INFO = "-show_trusted_devices_Info";

class AVSessionDumperAnotherTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionDumperAnotherTest::SetUpTestCase()
{
}

void AVSessionDumperAnotherTest::TearDownTestCase()
{
}

void AVSessionDumperAnotherTest::SetUp()

{
}

void AVSessionDumperAnotherTest::TearDown()
{
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowHelp, TestSize.Level1)
{
    SLOGI("Dump__ShowHelp begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_HELP);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);

    std::string resultExpect = "";
    resultExpect.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-show_metadata               :show all avsession metadata in the system\n")
        .append("-show_session_info           :show information of all sessions\n")
        .append("-show_controller_info        :show information of all controllers \n")
		
        .append("-show_error_info             :show error information about avsession\n")
        .append("-show_trusted_devices_Info   :show trusted devices Info\n");
    EXPECT_EQ(result, resultExpect);

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowHelp end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowMetaData, TestSize.Level1)
{
    SLOGI("Dump__ShowMetaData begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_METADATA);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());
	
    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowMetaData end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_AUDIO, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_AUDIO begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_SESSION_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);


    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;
	

    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_AUDIO end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VIDEO, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_SESSION_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_SESSION_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VOICE_CALL end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL, TestSize.Level1)
{
    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL begin!");
	
    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_SESSION_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowSessionInfo__SESSION_TYPE_VIDEO_CALL end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowControllerInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowControllerInfo begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
	
    args.push_back(ARGS_SHOW_CONTROLLER_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowControllerInfo end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowErrorInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowErrorInfo begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_SHOW_ERROR_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
	
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string resultExpect = "No Error Information!\n";
    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_EQ(result, resultExpect);

    std::string inErrMsg = "inErrMsg";
    avSessionDumper.SetErrorInfo(inErrMsg);
    result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowErrorInfo end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowTrustedDevicesInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowTrustedDevicesInfo begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_TRUSTED_DEVICES_INFO);
	
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    EXPECT_NE(result, "");
    SLOGI("result: %{public}s", result.c_str());

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowTrustedDevicesInfo end!");
}

static HWTEST_F(AVSessionDumperAnotherTest, Dump__ShowIllegalInfo, TestSize.Level1)
{
    SLOGI("Dump__ShowIllegalInfo begin!");

    int32_t ret = AVSESSION_ERROR;

    AVSessionDumper avSessionDumper;
    std::vector<std::string> args = {};
    args.push_back(ARGS_TRUSTED_DEVICES_INFO);
    args.push_back(ARGS_TRUSTED_DEVICES_INFO);

    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    sptr<AVSessionService> sessionService = new AVSessionService(systemAbilityId, runOnCreate);
	
    sessionService->OnStart();

    sptr<IRemoteObject> sessionInner;
    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VIDEO_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    ret = sessionService->CreateSessionInner(tag, type, elementName, sessionInner);
    EXPECT_TRUE(sessionInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    sptr<AVSessionProxy> avSessionProxy = new AVSessionProxy(sessionInner);
    std::string sessionId = avSessionProxy->GetSessionId();
    sptr<IRemoteObject> controllerInner;
    ret = sessionService->CreateControllerInner(sessionId, controllerInner);
    EXPECT_TRUE(controllerInner != nullptr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    std::string result = "";
    avSessionDumper.Dump(args, result, *sessionService);
    std::string resultExpect = ILLEGAL_INFORMATION;
    EXPECT_EQ(result, resultExpect);

    sessionService->OnStop();
    sessionService = nullptr;
    avSessionProxy = nullptr;

    SLOGI("Dump__ShowIllegalInfo end!");
}