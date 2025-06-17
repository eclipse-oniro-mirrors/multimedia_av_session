/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "avplayback_state.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVPlaybackStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVPlaybackStateTest::SetUpTestCase()
{}

void AVPlaybackStateTest::TearDownTestCase()
{}

void AVPlaybackStateTest::SetUp()
{}

void AVPlaybackStateTest::TearDown()
{}

/**
* @tc.name: SetState001
* @tc.desc: Setting State with empty constructor
* @tc.type: FUNC
* @tc.require: AR000H31JM
*/
HWTEST_F(AVPlaybackStateTest, SetState001, TestSize.Level0)
{
    auto *avp = new (std::nothrow) AVPlaybackState();
    EXPECT_NE(avp, nullptr);
    avp->SetState(0);
    avp->SetSpeed(3.0);
    avp->SetLoopMode(1);
    avp->SetBufferedTime(40);
    avp->SetPosition({10, 10});
    avp->SetFavorite(true);
    avp->SetActiveItemId(7);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    EXPECT_NE(parcel, nullptr);
    bool boo = avp->Marshalling(*parcel);
    EXPECT_EQ(boo, true);
}

/**
* @tc.name: IsValid001
* @tc.desc: Return is avplaybackstate IsValid success
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, IsValid001, TestSize.Level0)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetState(1);
    avPlaybackState.SetSpeed(3.0);
    avPlaybackState.SetLoopMode(1);
    avPlaybackState.SetBufferedTime(40);
    avPlaybackState.SetPosition({10, 10});
    avPlaybackState.SetFavorite(true);
    avPlaybackState.SetActiveItemId(7);

    EXPECT_EQ(avPlaybackState.IsValid(), true);
}

/**
* @tc.name: IsValid002
* @tc.desc: Return is avplaybackstate IsValid failed
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, IsValid002, TestSize.Level0)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetState(-1);
    avPlaybackState.SetSpeed(3.0);
    avPlaybackState.SetLoopMode(1);
    avPlaybackState.SetBufferedTime(40);
    avPlaybackState.SetPosition({10, 10});
    avPlaybackState.SetFavorite(true);
    avPlaybackState.SetActiveItemId(7);

    EXPECT_EQ(avPlaybackState.IsValid(), false);
}

/**
* @tc.name: GetState001
* @tc.desc: Getting state after using parcel to set
* @tc.type: FUNC
* @tc.require: AR000H31JM
*/
HWTEST_F(AVPlaybackStateTest, GetState001, TestSize.Level0)
{
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    EXPECT_NE(parcel, nullptr);
    AVPlaybackState::PlaybackStateMaskType mask;
    mask.set();
    parcel->WriteString(mask.to_string());
    parcel->WriteInt32(0);
    parcel->WriteDouble(3.0);
    parcel->WriteInt64(30);
    parcel->WriteInt64(3);
    parcel->WriteInt64(3);
    parcel->WriteInt32(3);
    parcel->WriteBool(true);
    parcel->WriteInt32(7);
    parcel->WriteInt32(0);
    parcel->WriteInt32(0);
    parcel->WriteBool(false);
    parcel->WriteInt32(0);
    parcel->WriteInt32(0);
    parcel->WriteInt32(0);

    AVPlaybackState *result = AVPlaybackState::Unmarshalling(*parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetFavorite(), true);
}

/**
* @tc.name: GetState002
* @tc.desc: Getting state after using marshalling to set
* @tc.type: FUNC
* @tc.require: AR000H31JM
*/
HWTEST_F(AVPlaybackStateTest, GetState002, TestSize.Level0)
{
    auto *avp = new (std::nothrow) AVPlaybackState();
    EXPECT_NE(avp, nullptr);
    avp->SetSpeed(3.0);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    EXPECT_NE(parcel, nullptr);
    bool boo = avp->Marshalling(*parcel);
    ASSERT_EQ(boo, true);
    AVPlaybackState *result = AVPlaybackState::Unmarshalling(*parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetSpeed(), 3.0);
}

/**
* @tc.name: GetMask001
* @tc.desc: Return is avplaybackstate GetMask success
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, GetMask001, TestSize.Level0)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetState(0);
    avPlaybackState.SetSpeed(3.0);
    avPlaybackState.SetLoopMode(1);
    avPlaybackState.SetBufferedTime(40);
    avPlaybackState.SetPosition({10, 10});
    avPlaybackState.SetFavorite(true);
    avPlaybackState.SetActiveItemId(7);

    EXPECT_EQ(avPlaybackState.GetMask(), 0b1111111);
}

/**
* @tc.name: CopyToByMask001
* @tc.desc: Return is avplaybackstate CopyToByMask success
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, CopyToByMask001, TestSize.Level0)
{
    AVPlaybackState stateOut;
    stateOut.SetSpeed(3.0);
    AVPlaybackState::PlaybackStateMaskType mask = stateOut.GetMask();

    AVPlaybackState stateTest;
    stateTest.SetSpeed(3.0);
    auto ret = stateTest.CopyToByMask(mask, stateOut);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: CopyToByMask002
* @tc.desc: Return is avplaybackstate CopyToByMask failed
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, CopyToByMask002, TestSize.Level0)
{
    AVPlaybackState stateOut;
    AVPlaybackState::PlaybackStateMaskType mask = stateOut.GetMask();

    AVPlaybackState stateTest;
    auto ret = stateTest.CopyToByMask(mask, stateOut);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: CopyFrom001
* @tc.desc: Return is avplaybackstate CopyFrom success
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, CopyFrom001, TestSize.Level0)
{
    AVPlaybackState stateOut;
    stateOut.SetSpeed(3.0);

    AVPlaybackState stateTest;
    auto ret = stateTest.CopyFrom(stateOut);
    EXPECT_EQ(stateTest.GetSpeed(), 3.0);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: CopyFrom002
* @tc.desc: Return is avplaybackstate CopyFrom failed
* @tc.type: FUNC
* @tc.require: I5YMXD
*/
HWTEST_F(AVPlaybackStateTest, CopyFrom002, TestSize.Level0)
{
    AVPlaybackState stateOut;

    AVPlaybackState stateTest;
    auto ret = stateTest.CopyFrom(stateOut);
    EXPECT_EQ(ret, false);
}
} // namespace AVSession
} // namespace OHOS
