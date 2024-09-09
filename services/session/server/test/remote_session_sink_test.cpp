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

sptr <AVSessionService> avservice = nullptr;
sptr <AVSessionItem> avsession = nullptr;
std::shared_ptr<RemoteSessionSink> remoteSessionSink;

class RemoteSessionSinkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteSessionSinkTest::SetUpTestCase()
{
    system("killall -9 com.example.hiMusicDemo");
    sleep(1);
    avservice = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    avservice->InitKeyEvent();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("testRemoteSink.ohos.avsession");
    elementName.SetAbilityName("testRemoteSink.ability");
    avsession = avservice->CreateSessionInner("testRemoteSink", AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::string sessionId = avsession->GetSessionId();
    std::string sourceDevice = "sourceDevice";
    std::string sinkDevice = "sinkDevice";
    std::string sourceCapability = "sourceCapability";
    int32_t ret = avsession->CastAudioFromRemote(sessionId, sourceDevice, sinkDevice, sourceCapability);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    remoteSessionSink = avsession->remoteSink_;
    ASSERT_NE(remoteSessionSink, nullptr);
}

void RemoteSessionSinkTest::TearDownTestCase()
{
}

void RemoteSessionSinkTest::SetUp()
{
}

void RemoteSessionSinkTest::TearDown()
{
    SLOGI("tear down test function in AVSessionServiceTest");
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession != nullptr) {
        ret = avsession->Destroy();
        avsession = nullptr;
    }
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
    int32_t ret = remoteSessionSink->SetControlCommand(command);
    remoteSessionSink->CancelCastSession();
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
    int32_t ret = remoteSessionSink->SetCommonCommand(commonCommand, commandArgs);
    remoteSessionSink->CancelCastSession();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetCommonCommand002 end!");
}

}