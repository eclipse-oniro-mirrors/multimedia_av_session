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
#include "ipc_skeleton.h"
#include "timer.h"
#define private public
#define protected public
#include "permission_checker.h"
#undef protected
#undef private

using namespace OHOS;
using namespace OHOS::AVSession;
using namespace Security::AccessToken;

class PermissionCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PermissionCheckerTest::SetUpTestCase()
{
}

void PermissionCheckerTest::TearDownTestCase()
{
}

void PermissionCheckerTest::SetUp()
{
}

void PermissionCheckerTest::TearDown()
{
}

/**
 * @tc.name: CheckSystemPermission001
 * @tc.desc: Test CheckSystemPermission
 * @tc.type: FUNC
 */
static HWTEST_F(PermissionCheckerTest, CheckSystemPermission001, testing::ext::TestSize.Level0)
{
    SLOGI("CheckSystemPermission001 begin!");
    auto permissionChecker = PermissionChecker::GetInstance();
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    bool ret = permissionChecker.CheckSystemPermission(tokenId);
    EXPECT_EQ(ret, true);
    SLOGI("CheckSystemPermission001 end!");
}

/**
 * @tc.name: CheckPermission001
 * @tc.desc: Test CheckSystemPermission
 * @tc.type: FUNC
 */
static HWTEST_F(PermissionCheckerTest, CheckPermission001, testing::ext::TestSize.Level0)
{
    SLOGI("CheckPermission001 begin!");
    auto permissionChecker = PermissionChecker::GetInstance();
    bool ret = permissionChecker.CheckPermission(-1);
    EXPECT_EQ(ret, false);
    SLOGI("CheckPermission001 end!");
}

/**
 * @tc.name: CheckSystemPermissionByUid001
 * @tc.desc: Test CheckSystemPermissionByUid
 * @tc.type: FUNC
 */
static HWTEST_F(PermissionCheckerTest, CheckSystemPermissionByUid001, testing::ext::TestSize.Level0)
{
    SLOGI("CheckSystemPermissionByUid001 begin!");
    auto permissionChecker = PermissionChecker::GetInstance();
    bool ret = permissionChecker.CheckSystemPermissionByUid(-1);
    EXPECT_EQ(ret, false);
    SLOGI("CheckSystemPermissionByUid001 end!");
}
