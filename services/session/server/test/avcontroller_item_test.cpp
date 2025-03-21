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

using namespace testing::ext;
using namespace OHOS::AVSession;

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

/**
* @tc.name: GetAVMetaData001
* @tc.desc: Test GetAVMetaData with no media image
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, GetAVMetaData001, TestSize.Level1)
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
HWTEST_F(AVControllerItemTest, GetAVMetaData002, TestSize.Level1)
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
HWTEST_F(AVControllerItemTest, GetAVMetaData003, TestSize.Level1)
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
HWTEST_F(AVControllerItemTest, SendCommonCommand001, TestSize.Level1)
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
* @tc.desc: Test GetAVMetaData with with not null migrateProxyCallback_
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, SendCommonCommand002, TestSize.Level1)
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
* @tc.name: Destroy001
* @tc.desc: Test GetAVMetaData with with sessionId_ is DEFAULT
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
HWTEST_F(AVControllerItemTest, Destroy001, TestSize.Level1)
{
    OHOS::sptr<AVControllerItem> controller = new AVControllerItem(1, g_AVSessionItem);
    ASSERT_TRUE(controller != nullptr);
    controller->sessionId_ = "DEFAULT";
    auto ret = controller->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
