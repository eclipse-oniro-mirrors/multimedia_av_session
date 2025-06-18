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
#define private public
#define protected public
#include "ability_manager_adapter.h"
#undef protected
#undef private
using namespace OHOS::AVSession;

class AbilityManagerAdapterDemoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityManagerAdapterDemoTest::SetUpTestCase()
{
}

void AbilityManagerAdapterDemoTest::TearDownTestCase()
{
}

void AbilityManagerAdapterDemoTest::SetUp()
{
}

void AbilityManagerAdapterDemoTest::TearDown()
{
}

/**
 * @tc.name: StartAbilityByCall001
 * @tc.desc: Test StartAbilityByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityManagerAdapterDemoTest, StartAbilityByCall001, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCall001 begin!");
    std::string sessionId = "001";
    std::string bundleName = "com.example.himusicdemo";
    std::string abilityName = "MainAbility";
    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);
    int32_t ret = abilityManagerAdapter.StartAbilityByCall(sessionId);
    EXPECT_EQ(ret, ERR_START_ABILITY_TIMEOUT);
    SLOGI("StartAbilityByCall001 end!");
}

/**
 * @tc.name: StartAbilityByCall002
 * @tc.desc: Test StartAbilityByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityManagerAdapterDemoTest, StartAbilityByCall002, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCall002 begin!");
    std::string sessionId = "002";
    std::string bundleName = "com.example.himusicdemo";
    std::string abilityName = "MainAbility";
    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);
    abilityManagerAdapter.status_ = Status::ABILITY_STATUS_RUNNING;
    int32_t ret = abilityManagerAdapter.StartAbilityByCall(sessionId);
    EXPECT_EQ(ret, ERR_START_ABILITY_IS_RUNNING);
    SLOGI("StartAbilityByCall002 end!");
}

/**
 * @tc.name: StartAbilityByCall003
 * @tc.desc: Test StartAbilityByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityManagerAdapterDemoTest, StartAbilityByCall003, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCall003 begin!");
    std::string sessionId = "003";
    std::string abilityName = "MainAbility";
    std::string bundleName = "com.ohos.camera";
    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);
    int32_t ret = abilityManagerAdapter.StartAbilityByCall(sessionId);
    EXPECT_EQ(ret, ERR_START_ABILITY_TIMEOUT);
    SLOGI("StartAbilityByCall003 end!");
}

/**
 * @tc.name: StartAbilityByCallDone001
 * @tc.desc: Test StartAbilityByCallDone
 * @tc.type: FUNC
 */
static HWTEST(AbilityManagerAdapterDemoTest, StartAbilityByCallDone001, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCallDone001 begin!");
    std::string sessionId = "001";
    std::string bundleName = "com.ohos.camera";
    std::string abilityName = "MainAbility";
    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);
    abilityManagerAdapter.StartAbilityByCallDone(sessionId);
    SLOGI("StartAbilityByCallDone001 end!");
}

/**
 * @tc.name: StartAbilityByCallDone002
 * @tc.desc: Test StartAbilityByCallDone
 * @tc.type: FUNC
 */
static HWTEST(AbilityManagerAdapterDemoTest, StartAbilityByCallDone002, testing::ext::TestSize.Level0)
{
    SLOGI("StartAbilityByCallDone002 begin!");
    std::string sessionId = "001";
    std::string bundleName = "com.ohos.camera";
    std::string abilityName = "MainAbility";
    AbilityManagerAdapter abilityManagerAdapter(bundleName, abilityName);
    abilityManagerAdapter.status_ = Status::ABILITY_STATUS_RUNNING;
    abilityManagerAdapter.StartAbilityByCallDone(sessionId);
    SLOGI("StartAbilityByCallDone002 end!");
}