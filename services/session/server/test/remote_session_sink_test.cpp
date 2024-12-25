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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "av_session.h"
#include "avsession_item.h"
#include "avsession_service.h"
#include "avsession_info.h"
#include "remote_session_sink_impl.h"
#include "remote_session_sink_proxy.h"

namespace OHOS::AVSession {

sptr <AVSessionService> g_AVSessionService = nullptr;
sptr <AVSessionItem> g_AVSessionItem = nullptr;
std::shared_ptr<RemoteSessionSink> g_RemoteSessionSink;

class RemoteSessionSinkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteSessionSinkTest::SetUpTestCase()
{
    g_AVSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("testRemoteSink.ohos.g_AVSessionItem");
    elementName.SetAbilityName("testRemoteSink.ability");
    g_AVSessionItem = g_AVSessionService->CreateSessionInner("testRemoteSink",
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::string sessionId = g_AVSessionItem->GetSessionId();
    std::string sourceDevice = "sourceDevice";
    std::string sinkDevice = "sinkDevice";
    std::string sourceCapability = "sourceCapability";
    g_RemoteSessionSink = std::make_shared<RemoteSessionSinkProxy>();
    g_RemoteSessionSink->CastSessionFromRemote(g_AVSessionItem, sessionId, sourceDevice, sinkDevice, sourceCapability);
    ASSERT_NE(g_RemoteSessionSink, nullptr);
}

void RemoteSessionSinkTest::TearDownTestCase()
{
    g_RemoteSessionSink->CancelCastSession();
    g_AVSessionService->Close();
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (g_AVSessionItem != nullptr) {
        ret = g_AVSessionItem->Destroy();
        g_AVSessionItem = nullptr;
    }
}

void RemoteSessionSinkTest::SetUp()
{
}

void RemoteSessionSinkTest::TearDown()
{
}

/**
 * @tc.name: SetControlCommand001
 * @tc.desc: Test SetControlCommand
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSinkTest, SetControlCommand001, testing::ext::TestSize.Level1)
{
    SLOGI("SetControlCommand001 begin!");
    AVControlCommand command;
    command.SetCommand(1000);
    int32_t ret = g_RemoteSessionSink->SetControlCommand(command);
    g_RemoteSessionSink->CancelCastSession();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetControlCommand001 end!");
}

/**
 * @tc.name: SetCommonCommand002
 * @tc.desc: Test SetCommonCommand
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSinkTest, SetCommonCommand002, testing::ext::TestSize.Level1)
{
    SLOGI("SetCommonCommand002 begin!");
    std::string commonCommand = "";
    AAFwk::WantParams commandArgs;
    int32_t ret = g_RemoteSessionSink->SetCommonCommand(commonCommand, commandArgs);
    g_RemoteSessionSink->CancelCastSession();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetCommonCommand002 end!");
}

}