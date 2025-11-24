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

#define private public
#include <gtest/gtest.h>
#include "avsession_whitelist_config_manager.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

namespace OHOS {
namespace AVSession {
class AVSessionWhitelistConfigManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AVSessionWhitelistConfigManager> avsessionWhitelistConfigManager;
};

void AVSessionWhitelistConfigManagerTest::SetUpTestCase(void)
{}

void AVSessionWhitelistConfigManagerTest::TearDownTestCase(void)
{}

void AVSessionWhitelistConfigManagerTest::SetUp(void)
{
    avsessionWhitelistConfigManager = DelayedSingleton<AVSessionWhitelistConfigManager>::GetInstance();
}

void AVSessionWhitelistConfigManagerTest::TearDown(void)
{}

/**
 * @tc.name: IsKeyEventSupported_001
 * @tc.desc: IsKeyEventSupported test with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, IsKeyEventSupported_001, TestSize.Level1)
{
    std::string bundleName = "";
    bool ret = avsessionWhitelistConfigManager->IsKeyEventSupported(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsKeyEventSupported_002
 * @tc.desc: IsKeyEventSupported test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, IsKeyEventSupported_002, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    bool ret = avsessionWhitelistConfigManager->IsKeyEventSupported(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsKeyEventSupported_003
 * @tc.desc: IsKeyEventSupported test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, IsKeyEventSupported_003, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    avsessionWhitelistConfigManager->isSettingsDataLoaded_ = true;
    bool ret = avsessionWhitelistConfigManager->IsKeyEventSupported(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsKeyEventSupported_004
 * @tc.desc: IsKeyEventSupported test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, IsKeyEventSupported_004, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    avsessionWhitelistConfigManager->isSettingsDataLoaded_ = false;
    bool ret = avsessionWhitelistConfigManager->IsKeyEventSupported(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSupportKeyEventFromSettings_001
 * @tc.desc: GetSupportKeyEventFromSettings test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, GetSupportKeyEventFromSettings_001, TestSize.Level1)
{
    std::string bundleName = "";
    bool ret = avsessionWhitelistConfigManager->GetSupportKeyEventFromSettings(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSupportKeyEventFromSettings_002
 * @tc.desc: GetSupportKeyEventFromSettings test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, GetSupportKeyEventFromSettings_002, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    bool ret = avsessionWhitelistConfigManager->GetSupportKeyEventFromSettings(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CreateDataShareHelper_001
 * @tc.desc: CreateDataShareHelper test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, CreateDataShareHelper_001, TestSize.Level1)
{
    EXPECT_NE(avsessionWhitelistConfigManager, nullptr);
    std::shared_ptr<DataShare::DataShareHelper> helper = avsessionWhitelistConfigManager->CreateDataShareHelper();
    EXPECT_NE(helper, nullptr);
}

/**
 * @tc.name: ReleaseDataShareHelper_001
 * @tc.desc: ReleaseDataShareHelper test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ReleaseDataShareHelper_001, TestSize.Level1)
{
    std::shared_ptr<DataShare::DataShareHelper> helper =  nullptr;
    bool ret = avsessionWhitelistConfigManager->ReleaseDataShareHelper(helper);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReleaseDataShareHelper_002
 * @tc.desc: ReleaseDataShareHelper test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ReleaseDataShareHelper_002, TestSize.Level1)
{
    std::shared_ptr<DataShare::DataShareHelper> helper =  avsessionWhitelistConfigManager->CreateDataShareHelper();
    bool ret = avsessionWhitelistConfigManager->ReleaseDataShareHelper(helper);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ParseJsonToMap_001
 * @tc.desc: ParseJsonToMap test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ParseJsonToMap_001, TestSize.Level1)
{
    std::string jsonStr = "";
    std::map<std::string, bool> compatibleInfoMap;
    bool ret = avsessionWhitelistConfigManager->ParseJsonToMap(jsonStr, compatibleInfoMap);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ParseJsonToMap_002
 * @tc.desc: ParseJsonToMap test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ParseJsonToMap_002, TestSize.Level1)
{
    std::string jsonStr = "{\"testBundle1\":true,\"testBundle2\":true}";
    std::map<std::string, bool> compatibleInfoMap;
    bool ret = avsessionWhitelistConfigManager->ParseJsonToMap(jsonStr, compatibleInfoMap);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(compatibleInfoMap.size(), 2);
    EXPECT_EQ(compatibleInfoMap["testBundle1"], true);
    EXPECT_EQ(compatibleInfoMap["testBundle2"], true);
}

/**
 * @tc.name: ParseJsonToMap_003
 * @tc.desc: ParseJsonToMap test
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ParseJsonToMap_003, TestSize.Level1)
{
    std::string jsonStr = "jsonstr";
    std::map<std::string, bool> compatibleInfoMap;
    bool ret = avsessionWhitelistConfigManager->ParseJsonToMap(jsonStr, compatibleInfoMap);
    EXPECT_EQ(ret, false);
}

} // namespace AVSession
} // namespace OHOS