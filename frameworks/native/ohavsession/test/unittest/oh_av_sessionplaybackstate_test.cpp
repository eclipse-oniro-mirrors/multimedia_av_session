/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <gtest/gtest.h>
#include "OHAVSessionPlaybackState.h"
#include "native_avplaybackstate.h"
#include "avsession_log.h"

using namespace testing::ext;
namespace OHOS::AVSession {
class OHAVSessionPlaybackStateTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHAVSessionPlaybackStateTest::SetUpTestCase(void)
{
}

void OHAVSessionPlaybackStateTest::TearDownTestCase(void)
{
}

void OHAVSessionPlaybackStateTest::SetUp()
{
}

void OHAVSessionPlaybackStateTest::TearDown()
{
}

/**
 * @tc.name: OHAVSessionPlaybackState_SetGetState_001
 * @tc.desc: Cover atomic state_ store/load round-trip
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OHAVSessionPlaybackState_SetGetState_001, TestSize.Level0)
{
    SLOGI("OHAVSessionPlaybackState_SetGetState_001 Begin");
    OHAVSessionPlaybackState playbackState;
    EXPECT_EQ(playbackState.GetState(), OHAVSessionPlaybackState::PLAYBACK_STATE_INITIAL);

    playbackState.SetState(OHAVSessionPlaybackState::PLAYBACK_STATE_PLAY);
    EXPECT_EQ(playbackState.GetState(), OHAVSessionPlaybackState::PLAYBACK_STATE_PLAY);

    playbackState.SetState(OHAVSessionPlaybackState::PLAYBACK_STATE_PAUSE);
    EXPECT_EQ(playbackState.GetState(), OHAVSessionPlaybackState::PLAYBACK_STATE_PAUSE);

    playbackState.SetState(OHAVSessionPlaybackState::PLAYBACK_STATE_STOP);
    EXPECT_EQ(playbackState.GetState(), OHAVSessionPlaybackState::PLAYBACK_STATE_STOP);
    SLOGI("OHAVSessionPlaybackState_SetGetState_001 End");
}

/**
 * @tc.name: OHAVSessionPlaybackState_SetGetPosition_001
 * @tc.desc: Cover atomic elapsedTime_/updateTime_ store/load round-trip
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OHAVSessionPlaybackState_SetGetPosition_001, TestSize.Level0)
{
    SLOGI("OHAVSessionPlaybackState_SetGetPosition_001 Begin");
    OHAVSessionPlaybackState playbackState;
    OHAVSessionPlaybackState::Position position = playbackState.GetPosition();
    EXPECT_EQ(position.elapsedTime_, 0);
    EXPECT_EQ(position.updateTime_, 0);

    OHAVSessionPlaybackState::Position newPosition;
    newPosition.elapsedTime_ = 1000;
    newPosition.updateTime_ = 2000;
    playbackState.SetPosition(newPosition);
    position = playbackState.GetPosition();
    EXPECT_EQ(position.elapsedTime_, 1000);
    EXPECT_EQ(position.updateTime_, 2000);

    newPosition.elapsedTime_ = -500;
    newPosition.updateTime_ = INT64_MAX;
    playbackState.SetPosition(newPosition);
    position = playbackState.GetPosition();
    EXPECT_EQ(position.elapsedTime_, -500);
    EXPECT_EQ(position.updateTime_, INT64_MAX);
    SLOGI("OHAVSessionPlaybackState_SetGetPosition_001 End");
}

/**
 * @tc.name: OHAVSessionPlaybackState_SetGetSpeed_001
 * @tc.desc: Cover atomic speed_ store/load round-trip
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OHAVSessionPlaybackState_SetGetSpeed_001, TestSize.Level0)
{
    SLOGI("OHAVSessionPlaybackState_SetGetSpeed_001 Begin");
    OHAVSessionPlaybackState playbackState;
    EXPECT_DOUBLE_EQ(playbackState.GetSpeed(), 1.0);

    playbackState.SetSpeed(2.5);
    EXPECT_DOUBLE_EQ(playbackState.GetSpeed(), 2.5);

    playbackState.SetSpeed(0.0);
    EXPECT_DOUBLE_EQ(playbackState.GetSpeed(), 0.0);

    playbackState.SetSpeed(-1.5);
    EXPECT_DOUBLE_EQ(playbackState.GetSpeed(), -1.5);
    SLOGI("OHAVSessionPlaybackState_SetGetSpeed_001 End");
}

/**
 * @tc.name: OHAVSessionPlaybackState_SetGetVolume_001
 * @tc.desc: Cover atomic volume_ store/load round-trip
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OHAVSessionPlaybackState_SetGetVolume_001, TestSize.Level0)
{
    SLOGI("OHAVSessionPlaybackState_SetGetVolume_001 Begin");
    OHAVSessionPlaybackState playbackState;
    EXPECT_EQ(playbackState.GetVolume(), 0);

    playbackState.SetVolume(30);
    EXPECT_EQ(playbackState.GetVolume(), 30);

    playbackState.SetVolume(-1);
    EXPECT_EQ(playbackState.GetVolume(), -1);

    playbackState.SetVolume(INT32_MAX);
    EXPECT_EQ(playbackState.GetVolume(), INT32_MAX);
    SLOGI("OHAVSessionPlaybackState_SetGetVolume_001 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackState_001
 * @tc.desc: Cover OH_AVSession_GetPlaybackState null playbState branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackState_001, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackState_001 Begin");
    AVSession_PlaybackState state = PLAYBACK_STATE_INITIAL;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackState(nullptr, &state);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    SLOGI("OH_AVSession_GetPlaybackState_001 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackState_002
 * @tc.desc: Cover OH_AVSession_GetPlaybackState null state branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackState_002, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackState_002 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackState(ohPlaybackState, nullptr);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackState_002 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackState_003
 * @tc.desc: Cover OH_AVSession_GetPlaybackState success branch with correct value
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackState_003, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackState_003 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    playbackState->SetState(OHAVSessionPlaybackState::PLAYBACK_STATE_PLAY);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_PlaybackState state = PLAYBACK_STATE_INITIAL;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackState(ohPlaybackState, &state);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(state, PLAYBACK_STATE_PLAYING);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackState_003 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackPosition_001
 * @tc.desc: Cover OH_AVSession_GetPlaybackPosition null playbState branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackPosition_001, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackPosition_001 Begin");
    AVSession_PlaybackPosition position = { 0, 0 };
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackPosition(nullptr, &position);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    SLOGI("OH_AVSession_GetPlaybackPosition_001 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackPosition_002
 * @tc.desc: Cover OH_AVSession_GetPlaybackPosition null position branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackPosition_002, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackPosition_002 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackPosition(ohPlaybackState, nullptr);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackPosition_002 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackPosition_003
 * @tc.desc: Cover OH_AVSession_GetPlaybackPosition success branch with correct value
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackPosition_003, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackPosition_003 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OHAVSessionPlaybackState::Position newPosition;
    newPosition.elapsedTime_ = 12345;
    newPosition.updateTime_ = 67890;
    playbackState->SetPosition(newPosition);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_PlaybackPosition position = { 0, 0 };
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackPosition(ohPlaybackState, &position);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(position.elapsedTime, 12345);
    EXPECT_EQ(position.updateTime, 67890);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackPosition_003 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_001
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed null playbState branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_001, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_001 Begin");
    int32_t speed = 0;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(nullptr, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    SLOGI("OH_AVSession_GetPlaybackSpeed_001 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_002
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed null speed branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_002, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_002 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, nullptr);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackSpeed_002 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_003
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed non-finite speed (NaN/Inf) branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_003, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_003 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    int32_t speed = 0;

    playbackState->SetSpeed(std::numeric_limits<double>::quiet_NaN());
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);

    playbackState->SetSpeed(std::numeric_limits<double>::infinity());
    ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);

    playbackState->SetSpeed(-std::numeric_limits<double>::infinity());
    ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackSpeed_003 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_004
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed negative speed branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_004, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_004 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    playbackState->SetSpeed(-1.5);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    int32_t speed = 0;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackSpeed_004 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_005
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed speed greater than INT32_MAX branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_005, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_005 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    playbackState->SetSpeed(static_cast<double>(INT32_MAX) + 1.0);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    int32_t speed = 0;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackSpeed_005 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackSpeed_006
 * @tc.desc: Cover OH_AVSession_GetPlaybackSpeed success branch with correct int value
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackSpeed_006, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackSpeed_006 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    int32_t speed = 0;

    playbackState->SetSpeed(1.0);
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(speed, 1);

    playbackState->SetSpeed(2.0);
    ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(speed, 2);

    playbackState->SetSpeed(1.5);
    ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(speed, 1);

    playbackState->SetSpeed(0.0);
    ret = OH_AVSession_GetPlaybackSpeed(ohPlaybackState, &speed);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(speed, 0);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackSpeed_006 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackVolume_001
 * @tc.desc: Cover OH_AVSession_GetPlaybackVolume null playbState branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackVolume_001, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackVolume_001 Begin");
    int32_t volume = 0;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackVolume(nullptr, &volume);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    SLOGI("OH_AVSession_GetPlaybackVolume_001 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackVolume_002
 * @tc.desc: Cover OH_AVSession_GetPlaybackVolume null volume branch
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackVolume_002, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackVolume_002 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackVolume(ohPlaybackState, nullptr);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackVolume_002 End");
}

/**
 * @tc.name: OH_AVSession_GetPlaybackVolume_003
 * @tc.desc: Cover OH_AVSession_GetPlaybackVolume success branch with correct value
 * @tc.type: FUNC
 * @tc.require: #2099
 */
HWTEST_F(OHAVSessionPlaybackStateTest, OH_AVSession_GetPlaybackVolume_003, TestSize.Level0)
{
    SLOGI("OH_AVSession_GetPlaybackVolume_003 Begin");
    OHAVSessionPlaybackState *playbackState = new (std::nothrow) OHAVSessionPlaybackState();
    ASSERT_NE(playbackState, nullptr);
    playbackState->SetVolume(66);
    OH_AVSession_AVPlaybackState *ohPlaybackState =
        reinterpret_cast<OH_AVSession_AVPlaybackState *>(playbackState);
    int32_t volume = 0;
    AVSession_ErrCode ret = OH_AVSession_GetPlaybackVolume(ohPlaybackState, &volume);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(volume, 66);
    delete playbackState;
    SLOGI("OH_AVSession_GetPlaybackVolume_003 End");
}
}
