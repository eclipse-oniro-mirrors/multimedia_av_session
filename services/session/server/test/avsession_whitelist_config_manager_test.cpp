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
#define private public
#include "avsession_whitelist_config_manager.h"
#undef private

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
    avsessionWhitelistConfigManager = AVSessionWhitelistConfigManager::GetInstance();
}

void AVSessionWhitelistConfigManagerTest::TearDown(void)
{}

#ifdef INPUT_REDISTRIBUTE_ENABLE
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
 * @tc.desc: IsKeyEventSupported test with a bundle that has no config entry
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, IsKeyEventSupported_002, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    bool ret = avsessionWhitelistConfigManager->IsKeyEventSupported(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSupportKeyEventFromConfig_001
 * @tc.desc: GetSupportKeyEventFromConfig test with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, GetSupportKeyEventFromConfig_001, TestSize.Level1)
{
    std::string bundleName = "";
    bool ret = avsessionWhitelistConfigManager->GetSupportKeyEventFromConfig(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetSupportKeyEventFromConfig_002
 * @tc.desc: GetSupportKeyEventFromConfig test with a bundle that has no config entry
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, GetSupportKeyEventFromConfig_002, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    bool ret = avsessionWhitelistConfigManager->GetSupportKeyEventFromConfig(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ResetReader_001
 * @tc.desc: ResetReader test on a manager without a reader
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, ResetReader_001, TestSize.Level1)
{
    EXPECT_NE(avsessionWhitelistConfigManager, nullptr);
    EXPECT_NO_FATAL_FAILURE(avsessionWhitelistConfigManager->ResetReader());
    EXPECT_EQ(avsessionWhitelistConfigManager->readerHandle_, nullptr);
}

/**
 * @tc.name: LoadConfigReaderLib_001
 * @tc.desc: LoadConfigReaderLib test, repeated load returns the cached handle state
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionWhitelistConfigManagerTest, LoadConfigReaderLib_001, TestSize.Level1)
{
    EXPECT_NE(avsessionWhitelistConfigManager, nullptr);
    bool first = avsessionWhitelistConfigManager->LoadConfigReaderLib();
    bool second = avsessionWhitelistConfigManager->LoadConfigReaderLib();
    EXPECT_EQ(first, second);
}
#endif

} // namespace AVSession
} // namespace OHOS
