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
#include "avplayback_state.h"
#include "remote_session_source_impl.h"
#include "remote_session_source_proxy.h"

namespace OHOS::AVSession {

sptr <AVSessionService> avservice = nullptr;
sptr <AVSessionItem> avsession = nullptr;
std::shared_ptr<RemoteSessionSource> remoteSessionSource;

class RemoteSessionSourceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteSessionSourceTest::SetUpTestCase()
{
    avservice = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    avservice->InitKeyEvent();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("testRemoteSource.ohos.avsession");
    elementName.SetAbilityName("testRemoteSource.ability");
    avsession = avservice->CreateSessionInner("testRemoteSource", AVSession::SESSION_TYPE_VOICE_CALL,
        false, elementName);
    int32_t ret = avsession->CastAudioToRemote("sourceDevice", "sinkDevice", "sinkCapability");
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    remoteSessionSource = avsession->GetRemoteSource();
    ASSERT_NE(remoteSessionSource, nullptr);
}

void RemoteSessionSourceTest::TearDownTestCase()
{
}

void RemoteSessionSourceTest::SetUp()
{
}

void RemoteSessionSourceTest::TearDown()
{
    SLOGI("tear down test function in AVSessionServiceTest");
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession != nullptr) {
        ret = avsession->Destroy();
        avsession = nullptr;
    }
}

/**
 * @tc.name: SetAVMetaData001
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVMetaData001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVMetaData001 begin!");
    AVMetaData metaData;
    int32_t ret = remoteSessionSource->SetAVMetaData(metaData);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVMetaData001 end!");
}

/**
 * @tc.name: SetAVPlaybackState001
 * @tc.desc: Test SetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVPlaybackState001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVPlaybackState001 begin!");
    AVPlaybackState state;
    int32_t ret = remoteSessionSource->SetAVPlaybackState(state);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVPlaybackState001 end!");
}

/**
 * @tc.name: SetSessionEventRemote001
 * @tc.desc: Test SetSessionEventRemote
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetSessionEventRemote001, testing::ext::TestSize.Level1)
{
    SLOGI("SetSessionEventRemote001 begin!");
    std::string event = "event";
    AAFwk::WantParams args;
    int32_t ret = remoteSessionSource->SetSessionEventRemote(event, args);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionEventRemote001 end!");
}

/**
 * @tc.name: SetAVQueueItems001
 * @tc.desc: Test SetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVQueueItems001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueItems001 begin!");
    std::vector<AVQueueItem> items;
    int32_t ret = remoteSessionSource->SetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVQueueItems001 end!");
}

/**
 * @tc.name: SetAVQueueTitle001
 * @tc.desc: Test SetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVQueueTitle001, testing::ext::TestSize.Level1)
{
    SLOGI("SetAVQueueTitle001 begin!");
    std::string title = "title";
    int32_t ret = remoteSessionSource->SetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetAVQueueTitle001 end!");
}

/**
 * @tc.name: GetSinkPlaybackStateMaskType001
 * @tc.desc: Test GetSinkPlaybackStateMaskType
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, GetSinkPlaybackStateMaskType001, testing::ext::TestSize.Level1)
{
    SLOGI("GetSinkPlaybackStateMaskType001 begin!");
    AAFwk::WantParams extras;
    int32_t ret = remoteSessionSource->SetExtrasRemote(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetSinkPlaybackStateMaskType001 end!");
}

}