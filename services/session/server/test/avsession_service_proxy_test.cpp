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
#include "avsession_log.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_service_proxy.h"

using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

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
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        }
    }
};

class AVSessionServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    OHOS::sptr<AVSessionServiceProxy> aVSessionServiceProxy;
    std::shared_ptr<AVSession> aVSession;
};

void AVSessionServiceProxyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVSessionServiceProxyTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionServiceProxyTest::SetUp()
{
    auto mgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGI("failed to get sa mgr");
        return;
    }
    auto object = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGI("failed to get service");
        return;
    }
    aVSessionServiceProxy = OHOS::iface_cast<AVSessionServiceProxy>(object);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
}

void AVSessionServiceProxyTest::TearDown()
{
}

/**
 * @tc.name: CreateSession001
 * @tc.desc: Test CreateSession
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, CreateSession001, testing::ext::TestSize.Level1)
{
    SLOGI("CreateSession001, start");
    OHOS::AppExecFwk::ElementName elementName;
    auto ret = aVSessionServiceProxy->CreateSession(g_testSessionTag,
        AVSession::SESSION_TYPE_AUDIO, elementName, aVSession);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
    SLOGI("CreateSession001, end");
}

/**
 * @tc.name: GetAllSessionDescriptors001
 * @tc.desc: Test GetAllSessionDescriptors
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetAllSessionDescriptors001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAllSessionDescriptors001, start");
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = aVSessionServiceProxy->GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetAllSessionDescriptors001, end");
}
