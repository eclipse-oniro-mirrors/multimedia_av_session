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
#include <chrono>
#include <thread>

#include "system_ability_definition.h"
#include "avsession_service.h"
#include "string_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {

static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static std::shared_ptr<MigrateAVSessionServer> g_MigrateAVSessionServer {nullptr};
static std::shared_ptr<AVSessionService> g_AVSessionService {nullptr};
static OHOS::sptr<AVSessionItem> g_AVSessionItem {nullptr};
static OHOS::sptr<AVControllerItem> g_AVControllerItem {nullptr};

class AVControllerItemTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AVControllerItemTest::SetUpTestCase()
{
    g_MigrateAVSessionServer = std::make_shared<MigrateAVSessionServer>();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    g_AVSessionService = std::make_shared<AVSessionService>(OHOS::AVSESSION_SERVICE_ID, true);
    g_AVSessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    g_AVControllerItem = g_AVSessionService->CreateNewControllerForSession(
        g_AVSessionItem->GetPid(), g_AVSessionItem);
}

void AVControllerItemTest::TearDownTestCase()
{
    g_AVSessionService->HandleSessionRelease(g_AVSessionItem->GetSessionId());
    g_AVControllerItem->Destroy();
    g_AVSessionItem->Destroy();
}

void AVControllerItemTest::SetUp()
{}

void AVControllerItemTest::TearDown()
{}

class IAVControllerCallbackTest : public IAVControllerCallback {
    ErrCode OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnAVCallStateChange(const AVCallState& avCallState) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionDestroy() override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnPlaybackStateChange(const AVPlaybackState& state) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnMetaDataChange(const AVMetaData& data) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnActiveStateChange(bool isActive) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnValidCommandChange(const std::vector<int32_t>& cmds) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionEventChange(const std::string& event, const OHOS::AAFwk::WantParams& ARGS) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnQueueItemsChange(const std::vector<AVQueueItem>& items) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnQueueTitleChange(const std::string& title) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnExtrasChange(const OHOS::AAFwk::WantParams& extras) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnCustomData(const OHOS::AAFwk::WantParams& data) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricVisibilityChanged(bool isVisible) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricStateChanged(const DesktopLyricState &state) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDesktopLyricEnabled(bool isEnabled) override
    {
        return AVSESSION_SUCCESS;
    };
    OHOS::sptr<IRemoteObject> AsObject() override
    {
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(g_testAnotherBundleName);
        elementName.SetAbilityName(g_testAnotherAbilityName);
        OHOS::sptr<AVSessionItem> avsessionHere_ = g_AVSessionService->CreateSessionInner(
            g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
        std::string sessionId = avsessionHere_->GetSessionId();
        OHOS::sptr<IRemoteObject> object = nullptr;
        g_AVSessionService->CreateControllerInner(sessionId, object);
        return object;
    }
};

/**
* @tc.name: GetAVMetaData001
* @tc.desc: Test GetAVMetaData with no media image
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, GetAVMetaData001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    AVMetaData metaData;
    auto ret = controller->GetAVMetaData(metaData);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetAVMetaData002
* @tc.desc: Test GetAVMetaData with media image
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, GetAVMetaData002, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    ASSERT_TRUE(mediaImage != nullptr);
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    mediaImage->SetInnerImgBuffer(imgBuffer);
    g_AVSessionItem->metaData_.SetMediaImage(mediaImage);
    g_AVSessionItem->metaData_.SetMediaImageUri(g_testSessionTag);
    AVMetaData metaData;
    auto ret = controller->GetAVMetaData(metaData);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
}

/**
* @tc.name: GetAVMetaData003
* @tc.desc: Test GetAVMetaData with media image, isFromSession_ is true
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, GetAVMetaData003, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    std::shared_ptr<AVSessionPixelMap> mediaImage = std::make_shared<AVSessionPixelMap>();
    ASSERT_TRUE(mediaImage != nullptr);
    std::vector<uint8_t> imgBuffer = {1, 2, 3, 4, 5, 6, 7, 8};
    mediaImage->SetInnerImgBuffer(imgBuffer);
    g_AVSessionItem->metaData_.SetMediaImage(mediaImage);
    g_AVSessionItem->metaData_.SetMediaImageUri(g_testSessionTag);
    controller->isFromSession_ = true;
    AVMetaData metaData;
    auto ret = controller->GetAVMetaData(metaData);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: SendCommonCommand001
* @tc.desc: Test SendCommonCommand with null migrateProxyCallback_
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, SendCommonCommand001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    std::string commonCommand;
    OHOS::AAFwk::WantParams commandArgs;
    auto ret = controller->SendCommonCommand(commonCommand, commandArgs);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: SendCommonCommand002
* @tc.desc: Test SendCommonCommand with with not null migrateProxyCallback_
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, SendCommonCommand002, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    std::string commonCommand;
    OHOS::AAFwk::WantParams commandArgs;
    controller->migrateProxyCallback_ = [](const std::string& event, OHOS::AAFwk::WantParams& args) {
        return AVSESSION_SUCCESS;
    };
    auto ret = controller->SendCommonCommand(commonCommand, commandArgs);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: SendCustomData001
* @tc.desc: Test SendCustomData with null migrateProxyCallback_
* @tc.type: FUNC
* @tc.require: #ICNHGY
*/
HWTEST_F(AVControllerItemTest, SendCustomData001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    std::string test = "test";
    OHOS::AAFwk::WantParams data;
    data.SetParam("customData", AAFwk::String::Box(test));

    auto ret = controller->SendCustomData(data);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: Destroy001
* @tc.desc: Test Destroy with with sessionId_ is DEFAULT
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, Destroy001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    controller->sessionId_ = "DEFAULT";
    auto ret = controller->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: HandleSessionDestroy001
* @tc.desc: Test HandleSessionDestroy with with callback_ is not nullptr
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, HandleSessionDestroy001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    controller->HandleSessionDestroy();
    EXPECT_EQ(controller->session_, nullptr);
}

/**
* @tc.name: HandleAVCallStateChange001
* @tc.desc: Test HandleAVCallStateChange with with callback_ is not nullptr
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, HandleAVCallStateChange001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    AVCallState callState;
    controller->HandleAVCallStateChange(callState);
    EXPECT_NE(controller->session_, nullptr);
}

/**
* @tc.name: HandleActiveStateChange001
* @tc.desc: Test HandleActiveStateChange with with callback_ is not nullptr
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, HandleActiveStateChange001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    controller->HandleActiveStateChange(false);
    EXPECT_NE(controller->session_, nullptr);
}


/**
* @tc.name: HandleCustomData001
* @tc.desc: handle customData
* @tc.type: FUNC
* @tc.require: #ICNHGY
*/
HWTEST_F(AVControllerItemTest, HandleCustomData001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    AAFwk::WantParams data;
    std::string test = "test";
    data.SetParam("customData", AAFwk::String::Box(test));
    controller->HandleCustomData(data);
    EXPECT_NE(controller->session_, nullptr);
}

/**
* @tc.name: HandleCustomData002
* @tc.desc: handle customData
* @tc.type: FUNC
* @tc.require: #ICNHGY
*/
HWTEST_F(AVControllerItemTest, HandleCustomData002, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    AAFwk::WantParams data;
    std::string test = "test";
    data.SetParam("customData", AAFwk::String::Box(test));
    controller->HandleCustomData(data);
    EXPECT_NE(controller->session_, nullptr);
}

/**
* @tc.name: IsDesktopLyricEnabled_001
* @tc.desc: get desktop lyric enabled state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVControllerItemTest, IsDesktopLyricEnabled_001, TestSize.Level1)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = false;
    bool isEnable = false;
    int32_t res = controller->IsDesktopLyricEnabled(isEnable);
    EXPECT_EQ(res, ERR_DESKTOPLYRIC_NOT_SUPPORT);
}

/**
* @tc.name: IsDesktopLyricEnabled_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVControllerItemTest, IsDesktopLyricEnabled_002, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    bool isEnable = false;
    int32_t res = controller->AVSessionController::IsDesktopLyricEnabled(isEnable);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
}

/**
* @tc.name: SetDesktopLyricVisible_001
* @tc.desc: set desktop lyric visible
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVControllerItemTest, SetDesktopLyricVisible_001, TestSize.Level1)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = false;
    bool isVisible = false;
    int32_t res = controller->SetDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, ERR_DESKTOPLYRIC_NOT_SUPPORT);
}

/**
* @tc.name: SetDesktopLyricVisible_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVControllerItemTest, SetDesktopLyricVisible_002, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    bool isVisible = false;
    int32_t res = controller->AVSessionController::SetDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
}

/**
* @tc.name: IsDesktopLyricVisible_001
* @tc.desc: get desktop lyric visible
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVControllerItemTest, IsDesktopLyricVisible_001, TestSize.Level1)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = false;
    bool isVisible = false;
    int32_t res = controller->IsDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, ERR_DESKTOPLYRIC_NOT_SUPPORT);
}

/**
* @tc.name: IsDesktopLyricVisible_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVControllerItemTest, IsDesktopLyricVisible_002, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    bool isVisible = false;
    int32_t res = controller->AVSessionController::IsDesktopLyricVisible(isVisible);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
}

/**
* @tc.name: SetDesktopLyricState_001
* @tc.desc: set desktop lyric state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVControllerItemTest, SetDesktopLyricState_001, TestSize.Level1)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = false;
    DesktopLyricState state = {};
    int32_t res = controller->SetDesktopLyricState(state);
    EXPECT_EQ(res, ERR_DESKTOPLYRIC_NOT_SUPPORT);
}

/**
* @tc.name: SetDesktopLyricState_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVControllerItemTest, SetDesktopLyricState_002, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    DesktopLyricState state = {};
    int32_t res = controller->AVSessionController::SetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetDesktopLyricState_001
* @tc.desc: get desktop lyric state
* @tc.type: FUNC
* @tc.require: #1990
*/
HWTEST_F(AVControllerItemTest, GetDesktopLyricState_001, TestSize.Level1)
{
    ASSERT_TRUE(g_AVSessionItem != nullptr);
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    g_AVSessionItem->isSupportedDesktopLyric_ = false;
    DesktopLyricState state = {};
    int32_t res = controller->GetDesktopLyricState(state);
    EXPECT_EQ(res, ERR_DESKTOPLYRIC_NOT_SUPPORT);
}

/**
* @tc.name: GetDesktopLyricState_002
* @tc.desc: covering the base class branch
* @tc.type: FUNC
* @tc.require: #2011
*/
HWTEST_F(AVControllerItemTest, GetDesktopLyricState_002, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    DesktopLyricState state = {};
    int32_t res = controller->AVSessionController::GetDesktopLyricState(state);
    EXPECT_EQ(res, AVSESSION_SUCCESS);
}

/**
* @tc.name: HandleDesktopLyricVisibilityChanged001
* @tc.desc: handle desktop lyric visibility changed
* @tc.type: FUNC
* @tc.require: #1998
*/
HWTEST_F(AVControllerItemTest, HandleDesktopLyricVisibilityChanged001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    controller->HandleDesktopLyricVisibilityChanged(true);
    EXPECT_NE(controller->session_, nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    controller->HandleDesktopLyricVisibilityChanged(true);
    EXPECT_NE(controller->session_, nullptr);
}

/**
* @tc.name: HandleDesktopLyricStateChanged001
* @tc.desc: handle desktop lyric state changed
* @tc.type: FUNC
* @tc.require: #1998
*/
HWTEST_F(AVControllerItemTest, HandleDesktopLyricStateChanged001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    DesktopLyricState state = {};
    controller->HandleDesktopLyricStateChanged(state);
    EXPECT_NE(controller->session_, nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    controller->HandleDesktopLyricStateChanged(state);
    EXPECT_NE(controller->session_, nullptr);
}

/**
* @tc.name: HandleDesktopLyricEnabled001
* @tc.desc: handle desktop lyric enabled
* @tc.type: FUNC
* @tc.require: #1998
*/
HWTEST_F(AVControllerItemTest, HandleDesktopLyricEnabled001, TestSize.Level0)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(getpid(), g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    controller->HandleDesktopLyricEnabled(false);
    EXPECT_NE(controller->session_, nullptr);
    OHOS::sptr<IAVControllerCallback> callback = new IAVControllerCallbackTest();
    ASSERT_TRUE(callback != nullptr);
    controller->callback_ = callback;
    controller->HandleDesktopLyricEnabled(false);
    EXPECT_NE(controller->session_, nullptr);
}
} //AVSession
} //OHOS