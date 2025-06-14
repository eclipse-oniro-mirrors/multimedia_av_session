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

sptr <AVSessionService> g_AVSessionService = nullptr;
sptr <AVSessionItem> g_AVSessionItem = nullptr;
std::shared_ptr<RemoteSessionSource> g_RemoteSessionSource;

class RemoteSessionSourceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteSessionSourceTest::SetUpTestCase()
{
    g_AVSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("testRemoteSource.ohos.g_AVSessionItem");
    elementName.SetAbilityName("testRemoteSource.ability");
    g_AVSessionItem = g_AVSessionService->CreateSessionInner("testRemoteSource",
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::string sourceDevice = "sourceDevice";
    std::string sinkDevice = "sinkDevice";
    std::string sinkCapability = "sinkCapability";
    g_RemoteSessionSource = std::make_shared<RemoteSessionSourceProxy>();
    ASSERT_NE(g_RemoteSessionSource, nullptr);
    g_RemoteSessionSource->CastSessionToRemote(g_AVSessionItem, sourceDevice, sinkDevice, sinkCapability);
}

void RemoteSessionSourceTest::TearDownTestCase()
{
    g_AVSessionItem->Destroy();
    g_AVSessionService->Close();
}

void RemoteSessionSourceTest::SetUp()
{
}

void RemoteSessionSourceTest::TearDown()
{
}

/**
 * @tc.name: SetAVMetaData001
 * @tc.desc: Test SetAVMetaData
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVMetaData001, testing::ext::TestSize.Level0)
{
    SLOGI("SetAVMetaData001 begin!");
    AVMetaData metaData;
    int32_t ret = g_RemoteSessionSource->SetAVMetaData(metaData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetAVMetaData001 end!");
}

/**
 * @tc.name: SetAVPlaybackState001
 * @tc.desc: Test SetAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVPlaybackState001, testing::ext::TestSize.Level0)
{
    SLOGI("SetAVPlaybackState001 begin!");
    AVPlaybackState state;
    int32_t ret = g_RemoteSessionSource->SetAVPlaybackState(state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetAVPlaybackState001 end!");
}

/**
 * @tc.name: SetSessionEventRemote001
 * @tc.desc: Test SetSessionEventRemote
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetSessionEventRemote001, testing::ext::TestSize.Level0)
{
    SLOGI("SetSessionEventRemote001 begin!");
    std::string event = "event";
    AAFwk::WantParams args;
    int32_t ret = g_RemoteSessionSource->SetSessionEventRemote(event, args);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetSessionEventRemote001 end!");
}

/**
 * @tc.name: SetAVQueueItems001
 * @tc.desc: Test SetAVQueueItems
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVQueueItems001, testing::ext::TestSize.Level0)
{
    SLOGI("SetAVQueueItems001 begin!");
    std::vector<AVQueueItem> items;
    int32_t ret = g_RemoteSessionSource->SetAVQueueItems(items);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetAVQueueItems001 end!");
}

/**
 * @tc.name: SetAVQueueTitle001
 * @tc.desc: Test SetAVQueueTitle
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, SetAVQueueTitle001, testing::ext::TestSize.Level0)
{
    SLOGI("SetAVQueueTitle001 begin!");
    std::string title = "title";
    int32_t ret = g_RemoteSessionSource->SetAVQueueTitle(title);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetAVQueueTitle001 end!");
}

/**
 * @tc.name: GetSinkPlaybackStateMaskType001
 * @tc.desc: Test GetSinkPlaybackStateMaskType
 * @tc.type: FUNC
 */
static HWTEST_F(RemoteSessionSourceTest, GetSinkPlaybackStateMaskType001, testing::ext::TestSize.Level0)
{
    SLOGI("GetSinkPlaybackStateMaskType001 begin!");
    AAFwk::WantParams extras;
    int32_t ret = g_RemoteSessionSource->SetExtrasRemote(extras);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetSinkPlaybackStateMaskType001 end!");
}

}