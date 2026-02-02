/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "avsession_manager.h"
#include "accesstoken_kit.h"
#include "bool_wrapper.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iavsession_controller.h"
#include "iremote_stub.h"
#include "want_params.h"
#include "ipc_skeleton.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "avsession_log.h"


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
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
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
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class AVSessionControllerClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSessionController> controller_ = nullptr;

    static constexpr int64_t TestMicroSecond = 1000;
};

void AVSessionControllerClientTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionControllerClientTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionControllerClientTest::SetUp()
{
    std::vector<AVSessionDescriptor> descriptors;
    auto retForGet = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
    ASSERT_EQ(retForGet, AVSESSION_SUCCESS);
    SLOGI("GetAllSessionDescriptors size:%{public}d", static_cast<int>(descriptors.size()));
    if (descriptors.size() > 0) {
        auto res = AVSessionManager::GetInstance().CreateController(descriptors[0].sessionId_, controller_);
        SLOGI("CreateController res:%{public}d", res);
        ASSERT_EQ(res, AVSESSION_SUCCESS);
        ASSERT_NE(controller_, nullptr);
    }
}

void AVSessionControllerClientTest::TearDown()
{
    if (controller_ != nullptr) {
        SLOGI("Destroy controller");
        controller_->Destroy();
    }
}

/**
* @tc.name: IsSessionActive001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerClientTest, IsSessionActive001, TestSize.Level1)
{
    bool active = false;
    if (controller_ != nullptr) {
        EXPECT_EQ(controller_->IsSessionActive(active), AVSESSION_SUCCESS);
    } else {
        std::vector<AVSessionDescriptor> descriptors;
        auto res = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
        ASSERT_EQ(res, AVSESSION_SUCCESS);
        EXPECT_EQ(descriptors.size() <= 0, true);
    }
}
} // namespace AVSession
} // namespace OHOS
