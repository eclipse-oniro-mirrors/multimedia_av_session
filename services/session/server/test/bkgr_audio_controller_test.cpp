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
#include "background_audio_controller.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "running_process_info.h"
#include "app_manager_adapter.h"
#include "bundle_mgr_client.h"
#include "avsession_descriptor.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class BkGrAudioControllerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BkGrAudioControllerTest::SetUpTestCase()
{}

void BkGrAudioControllerTest::TearDownTestCase()
{}

void BkGrAudioControllerTest::SetUp()
{}

void BkGrAudioControllerTest::TearDown()
{}

/**
* @tc.name: OnSessionRelease001
* @tc.desc: descriptor.isThirdPartyApp_ = false
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, OnSessionRelease001, TestSize.Level1)
{
    SLOGI("OnSessionRelease001 begin!");
    AVSessionDescriptor descriptor;
    descriptor.isThirdPartyApp_ = false;
    BackgroundAudioController bkgraudiocontroller;
    bkgraudiocontroller.OnSessionRelease(descriptor);
    EXPECT_EQ(descriptor.isThirdPartyApp_, false);
    SLOGI("OnSessionRelease001 end!");
}

/**
* @tc.name: OnSessionRelease002
* @tc.desc: descriptor.isThirdPartyApp_ = true&&descriptor.uid_ = -1
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, OnSessionRelease002, TestSize.Level1)
{
    SLOGI("OnSessionRelease002 begin!");
    AVSessionDescriptor descriptor;
    descriptor.isThirdPartyApp_ = false;
    descriptor.uid_ = -1;
    BackgroundAudioController bkgraudiocontroller;
    bkgraudiocontroller.OnSessionRelease(descriptor);
    EXPECT_EQ(descriptor.isThirdPartyApp_, false);
    SLOGI("OnSessionRelease002 end!");
}

/**
* @tc.name: OnSessionRelease003
* @tc.desc: descriptor.isThirdPartyApp_ = true&&descriptor.uid_ = 100
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, OnSessionRelease003, TestSize.Level1)
{
    SLOGI("OnSessionRelease003 begin!");
    AVSessionDescriptor descriptor;
    descriptor.isThirdPartyApp_ = false;
    descriptor.uid_ = 100;
    BackgroundAudioController bkgraudiocontroller;
    bkgraudiocontroller.OnSessionRelease(descriptor);
    EXPECT_EQ(descriptor.isThirdPartyApp_, false);
    SLOGI("OnSessionRelease032 end!");
}

/**
* @tc.name: HandleAudioStreamRendererStateChange001
* @tc.desc: info->rendererState != AudioStandard::RENDERER_RUNNING
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, HandleAudioStreamRendererStateChange001, TestSize.Level1)
{
    SLOGI("HandleAudioStreamRendererStateChange001 begin!");
    std::unique_ptr<OHOS::AudioStandard::AudioRendererChangeInfo> info =
        std::make_unique<OHOS::AudioStandard::AudioRendererChangeInfo>();
    std::vector<std::unique_ptr<OHOS::AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfos;
    info->rendererState = OHOS::AudioStandard::RENDERER_NEW;
    audioRendererChangeInfos.push_back(move(info));
    BackgroundAudioController backgroundaudiocontroller;
    backgroundaudiocontroller.HandleAudioStreamRendererStateChange(audioRendererChangeInfos);
    EXPECT_EQ(audioRendererChangeInfos[0]->rendererState, OHOS::AudioStandard::RENDERER_NEW);
}

/**
* @tc.name: HandleAudioStreamRendererStateChange002
* @tc.desc: !AppManagerAdapter::GetInstance().IsAppBackground(info->clientUID)
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, HandleAudioStreamRendererStateChange002, TestSize.Level1)
{
    SLOGI("HandleAudioStreamRendererStateChange002 begin!");
    std::unique_ptr<OHOS::AudioStandard::AudioRendererChangeInfo> info =
        std::make_unique<OHOS::AudioStandard::AudioRendererChangeInfo>();
    std::vector<std::unique_ptr<OHOS::AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfos;
    info->rendererState = OHOS::AudioStandard::RENDERER_RUNNING;
    info->clientUID = -1;
    audioRendererChangeInfos.push_back(move(info));
    BackgroundAudioController backgroundaudiocontroller;
    backgroundaudiocontroller.HandleAudioStreamRendererStateChange(audioRendererChangeInfos);
    EXPECT_EQ(audioRendererChangeInfos[0]->clientUID, -1);
}

/**
* @tc.name: HandleAppBackgroundState001
* @tc.desc: int32_t uid = -1;
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(BkGrAudioControllerTest, HandleAppBackgroundState001, TestSize.Level1)
{
    SLOGI("HandleAppBackgroundState001 begin!");
    int32_t uid = -1;
    BackgroundAudioController backgroundaudiocontroller;
    backgroundaudiocontroller.HandleAppBackgroundState(uid);
    EXPECT_EQ(uid, -1);
}

