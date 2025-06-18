/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "avcall_state.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVCallStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVCallStateTest::SetUpTestCase()
{}

void AVCallStateTest::TearDownTestCase()
{}

void AVCallStateTest::SetUp()
{}

void AVCallStateTest::TearDown()
{}

/**
 * @tc.name: SetAVCallState001
 * @tc.desc: Setting AVCallState with empty constructor
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, SetAVCallState001, TestSize.Level0)
{
    auto *avp = new (std::nothrow) AVCallState();
    EXPECT_NE(avp, nullptr);
    avp->SetAVCallState(1);
    avp->SetAVCallMuted(true);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    EXPECT_NE(parcel, nullptr);
    bool boo = avp->Marshalling(*parcel);
    EXPECT_EQ(boo, true);
}

/**
 * @tc.name: IsValid001
 * @tc.desc: Return is avcallstate IsValid success
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, IsValid001, TestSize.Level0)
{
    AVCallState avCallState;
    avCallState.SetAVCallState(2);
    avCallState.SetAVCallMuted(false);

    EXPECT_EQ(avCallState.IsValid(), true);
}

/**
 * @tc.name: IsValid002
 * @tc.desc: Return is avcallstate IsValid failed
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, IsValid002, TestSize.Level0)
{
    AVCallState avCallState;
    avCallState.SetAVCallState(-1);
    avCallState.SetAVCallMuted(false);

    EXPECT_EQ(avCallState.IsValid(), false);
}

/**
 * @tc.name: GetAVCallState001
 * @tc.desc: Getting avcall state after using marshalling to set
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, GetAVCallState001, TestSize.Level0)
{
    auto *avp = new (std::nothrow) AVCallState();
    EXPECT_NE(avp, nullptr);
    avp->SetAVCallState(3);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    EXPECT_NE(parcel, nullptr);
    bool boo = avp->Marshalling(*parcel);
    ASSERT_EQ(boo, true);
    AVCallState *result = AVCallState::Unmarshalling(*parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAVCallState(), 3);
}

/**
 * @tc.name: CopyToByMask001
 * @tc.desc: Return is avcallstate CopyToByMask success
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, CopyToByMask001, TestSize.Level0)
{
    AVCallState stateOut;
    stateOut.SetAVCallState(2);
    AVCallState::AVCallStateMaskType mask = stateOut.GetMask();

    AVCallState stateTest;
    stateTest.SetAVCallState(2);
    auto ret = stateTest.CopyToByMask(mask, stateOut);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CopyToByMask002
 * @tc.desc: Return is avcallstate CopyToByMask failed
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, CopyToByMask002, TestSize.Level0)
{
    AVCallState stateOut;
    AVCallState::AVCallStateMaskType mask = stateOut.GetMask();

    AVCallState stateTest;
    auto ret = stateTest.CopyToByMask(mask, stateOut);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CopyFrom001
 * @tc.desc: Return is avcallstate CopyFrom success
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, CopyFrom001, TestSize.Level0)
{
    AVCallState stateOut;
    stateOut.SetAVCallState(1);

    AVCallState stateTest;
    auto ret = stateTest.CopyFrom(stateOut);
    EXPECT_EQ(stateTest.GetAVCallState(), 1);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CopyFrom002
 * @tc.desc: Return is avcallstate CopyFrom failed
 * @tc.type: FUNC
 */
HWTEST_F(AVCallStateTest, CopyFrom002, TestSize.Level0)
{
    AVCallState stateOut;

    AVCallState stateTest;
    auto ret = stateTest.CopyFrom(stateOut);
    EXPECT_EQ(ret, false);
}
} // namespace AVSession
} // namespace OHOS