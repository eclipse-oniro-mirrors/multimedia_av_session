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
#include "insight_intent_execute_param.h"
#define private public
#define protected public
#include "bundle_status_adapter.h"
#undef protected
#undef private

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
static uint64_t g_selfTokenId = 0;

static HapInfoParams g_info = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demo",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demo",
    .isSystemApp = true
};

static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.LISTEN_BUNDLE_CHANGE",
            .bundleName = "ohos.permission_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.LISTEN_BUNDLE_CHANGE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class BundleStatusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BundleStatusAdapterTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void BundleStatusAdapterTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void BundleStatusAdapterTest::SetUp()
{
}

void BundleStatusAdapterTest::TearDown()
{
}

/**
 * @tc.name: SubscribeBundleStatusEvent001
 * @tc.desc: Test SubscribeBundleStatusEvent
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, SubscribeBundleStatusEvent001, testing::ext::TestSize.Level1)
{
    SLOGI("SubscribeBundleStatusEvent001, start");
    std::string bundleName = "test1";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("SubscribeBundleStatusEvent001: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    bool ret = BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    EXPECT_NE(ret, true);
    SLOGI("SubscribeBundleStatusEvent001, end");
}

/**
 * @tc.name: SubscribeBundleStatusEvent002
 * @tc.desc: Test SubscribeBundleStatusEvent
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, SubscribeBundleStatusEvent002, testing::ext::TestSize.Level1)
{
    SLOGI("SubscribeBundleStatusEvent002, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("SubscribeBundleStatusEvent002: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    bool ret = BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    EXPECT_EQ(ret, false);
    SLOGI("SubscribeBundleStatusEvent002, end");
}

/**
 * @tc.name: SubscribeBundleStatusEvent003
 * @tc.desc: Test SubscribeBundleStatusEvent
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, SubscribeBundleStatusEvent003, testing::ext::TestSize.Level1)
{
    SLOGI("SubscribeBundleStatusEvent003, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "com.ohos.sceneboard";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("SubscribeBundleStatusEvent003: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    bool ret = BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    EXPECT_EQ(ret, true);
    SLOGI("SubscribeBundleStatusEvent003, end");
}

/**
 * @tc.name: GetBundleNameFromUid001
 * @tc.desc: Test GetBundleNameFromUid
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, GetBundleNameFromUid001, testing::ext::TestSize.Level1)
{
    SLOGI("GetBundleNameFromUid001, start");
    BundleStatusAdapter::GetInstance().Init();
    const int32_t uid = 0;
    BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    EXPECT_EQ(uid, 0);
    SLOGI("GetBundleNameFromUid001, end");
}

/**
 * @tc.name: CheckBundleSupport001
 * @tc.desc: Test CheckBundleSupport
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, CheckBundleSupport001, testing::ext::TestSize.Level1)
{
    SLOGI("CheckBundleSupport001, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string profile = "";
    bool ret = BundleStatusAdapter::GetInstance().CheckBundleSupport(profile);
    EXPECT_EQ(ret, false);
    SLOGI("CheckBundleSupport001, end");
}

/**
 * @tc.name: CheckBundleSupport002
 * @tc.desc: Test CheckBundleSupport
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, CheckBundleSupport002, testing::ext::TestSize.Level1)
{
    SLOGI("CheckBundleSupport002, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string profile = R"({
        "insightIntents": [
            {
                "intentName": "OTHER_INTENT",
                "uiAbility": {
                    "executeMode": ["background"]
                }
            }
        ]
    })";
    bool ret = BundleStatusAdapter::GetInstance().CheckBundleSupport(profile);
    EXPECT_EQ(ret, false);
    SLOGI("CheckBundleSupport002, end");
}

/**
 * @tc.name: CheckBundleSupport003
 * @tc.desc: Test CheckBundleSupport
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, CheckBundleSupport003, testing::ext::TestSize.Level1)
{
    SLOGI("CheckBundleSupport003, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string profile = R"({
        "insightIntents": [
            {
                "intentName": "PLAY_MUSICLIST",
                "uiAbility": {
                    "executeMode": ["background"]
                }
            }
        ]
    })";
    bool ret = BundleStatusAdapter::GetInstance().CheckBundleSupport(profile);
    EXPECT_EQ(ret, false);
    SLOGI("CheckBundleSupport003, end");
}

/**
 * @tc.name: CheckBundleSupport004
 * @tc.desc: Test CheckBundleSupport
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, CheckBundleSupport004, testing::ext::TestSize.Level1)
{
    SLOGI("CheckBundleSupport004, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string profile = R"({
        "insightIntents": [
            {
                "intentName": "PLAY_AUDIO",
                "uiAbility": {
                    "executeMode": ["background"]
                }
            }
        ]
    })";
    bool ret = BundleStatusAdapter::GetInstance().CheckBundleSupport(profile);
    EXPECT_EQ(ret, false);
    SLOGI("CheckBundleSupport004, end");
}

/**
 * @tc.name: IsAudioPlayback001
 * @tc.desc: Test IsAudioPlayback
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, IsAudioPlayback001, testing::ext::TestSize.Level1)
{
    SLOGI("IsAudioPlayback001, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "";
    std::string abilityName = "";
    bool ret = BundleStatusAdapter::GetInstance().IsAudioPlayback(bundleName, abilityName);
    EXPECT_EQ(ret, false);
    SLOGI("IsAudioPlayback001, end");
}

/**
 * @tc.name: IsAudioPlayback002
 * @tc.desc: Test IsAudioPlayback
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, IsAudioPlayback002, testing::ext::TestSize.Level1)
{
    SLOGI("IsAudioPlayback002, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "com.ohos.screenshot";
    std::string abilityName = "MainAbility";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("SubscribeBundleStatusEvent003: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    bool ret = BundleStatusAdapter::GetInstance().IsAudioPlayback(bundleName, abilityName);
    EXPECT_EQ(ret, false);
    SLOGI("IsAudioPlayback002, end");
}

/**
 * @tc.name: NotifyBundleRemoved001
 * @tc.desc: Test NotifyBundleRemoved
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, NotifyBundleRemoved001, testing::ext::TestSize.Level1)
{
    SLOGI("NotifyBundleRemoved001, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "com.ohos.screenshot";
    std::string abilityName = "MainAbility";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("SubscribeBundleStatusEvent004: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    BundleStatusAdapter::GetInstance().NotifyBundleRemoved(bundleName, 100);
    EXPECT_EQ(bundleName, "com.ohos.screenshot");
    SLOGI("NotifyBundleRemoved001, end");
}

/**
 * @tc.name: NotifyBundleRemoved002
 * @tc.desc: Test NotifyBundleRemoved
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, NotifyBundleRemoved002, testing::ext::TestSize.Level1)
{
    SLOGI("NotifyBundleRemoved002, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "com.ohos.test";
    std::string abilityName = "MainAbility";
    BundleStatusAdapter::GetInstance().NotifyBundleRemoved(bundleName, 100);
    EXPECT_EQ(bundleName, "com.ohos.test");
    SLOGI("NotifyBundleRemoved002, end");
}

/**
 * @tc.name: IsSupportPlayIntent001
 * @tc.desc: Test IsSupportPlayIntent
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, IsSupportPlayIntent001, testing::ext::TestSize.Level1)
{
    SLOGI("IsSupportPlayIntent001, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "";
    std::string supportModule = "";
    std::string profile = "";
    bool ret = BundleStatusAdapter::GetInstance().IsSupportPlayIntent(bundleName, supportModule, profile);
    EXPECT_EQ(ret, false);
    SLOGI("IsSupportPlayIntent001, end");
}

/**
 * @tc.name: IsSupportPlayIntent002
 * @tc.desc: Test IsSupportPlayIntent
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, IsSupportPlayIntent002, testing::ext::TestSize.Level1)
{
    SLOGI("IsSupportPlayIntent002, start");
    BundleStatusAdapter::GetInstance().Init();
    std::string bundleName = "com.IsSupportPlayIntent.test";
    std::string supportModule = "";
    std::string profile = "";
    auto callback = [bundleName](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("IsSupportPlayIntent002: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
    };
    BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(bundleName, callback);
    bool ret = BundleStatusAdapter::GetInstance().IsSupportPlayIntent(bundleName, supportModule, profile);
    EXPECT_EQ(ret, false);
    SLOGI("IsSupportPlayIntent002, end");
}

/**
 * @tc.name: OnBundleStateChanged001
 * @tc.desc: Test OnBundleStateChanged
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, OnBundleStateChanged001, testing::ext::TestSize.Level1)
{
    bool ret = false;
    auto callback = [&ret](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("OnBundleStateChanged001: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
        ret = true;
    };
    sptr<BundleStatusCallbackImpl> bundleStatusCallbackImpl =
            new(std::nothrow) BundleStatusCallbackImpl(callback, 1);
    bundleStatusCallbackImpl->OnBundleStateChanged(1, 0, "test1", "");
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: OnBundleStateChanged002
 * @tc.desc: Test OnBundleStateChanged
 * @tc.type: FUNC
 */
static HWTEST_F(BundleStatusAdapterTest, OnBundleStateChanged002, testing::ext::TestSize.Level1)
{
    bool ret = true;
    auto callback = [&ret](const std::string& capturedBundleName, int32_t userId) {
        SLOGI("OnBundleStateChanged002: get bundle name: %{public}s, userId: %{public}d",
            capturedBundleName.c_str(), userId);
        ret = false;
    };
    sptr<BundleStatusCallbackImpl> bundleStatusCallbackImpl = new(std::nothrow) BundleStatusCallbackImpl(callback, 1);
    bundleStatusCallbackImpl->OnBundleStateChanged(0, 0, "test2", "");
    EXPECT_TRUE(ret);
}
} // namespace AVSession
} // namespace OHOS
