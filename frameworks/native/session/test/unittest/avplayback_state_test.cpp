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
using namespace OHOS::AVSession;
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
HWTEST_F(AVPlaybackStateTest, SetState001, TestSize.Level1)
{
    auto *avp = new (std::nothrow) AVPlaybackState();
    avp->SetState(0);
    avp->SetSpeed(3.0);
    avp->SetLoopMode(1);
    avp->SetBufferedTime(40);
    avp->SetPosition({ 10, 10 });
    avp->SetFavorite(true);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    bool boo = avp->Marshalling(*parcel);
    EXPECT_EQ(boo, true);
}

/**
* @tc.name: GetState001
* @tc.desc: Getting state after using parcel to set
* @tc.type: FUNC
* @tc.require: AR000H31JM
*/
HWTEST_F(AVPlaybackStateTest, GetState001, TestSize.Level1)
{
    auto *parcel = new (std::nothrow) OHOS::Parcel();
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
HWTEST_F(AVPlaybackStateTest, GetState002, TestSize.Level1)
{
    auto *avp = new (std::nothrow) AVPlaybackState();
    avp->SetSpeed(3.0);
    auto *parcel = new (std::nothrow) OHOS::Parcel();
    bool boo = avp->Marshalling(*parcel);
    ASSERT_EQ(boo, true);
    AVPlaybackState *result = AVPlaybackState::Unmarshalling(*parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetSpeed(), 3.0);
}