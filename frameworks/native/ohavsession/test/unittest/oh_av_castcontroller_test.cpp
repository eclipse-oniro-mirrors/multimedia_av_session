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

#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include "OHAVSession.h"
#include "OHAVCastController.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::AVSession {

class OHAVCastControllerCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHAVCastControllerCallbackImplTest::SetUpTestCase(void)
{
}

void OHAVCastControllerCallbackImplTest::TearDownTestCase(void)
{
}

void OHAVCastControllerCallbackImplTest::SetUp()
{
}

void OHAVCastControllerCallbackImplTest::TearDown()
{
}

class AVCastControllerMock : public AVCastController {
public:
    AVCastControllerMock() = default;
    virtual ~AVCastControllerMock() = default;
    MOCK_METHOD(int32_t, SendControlCommand, (const AVCastControlCommand& cmd), (override));
    MOCK_METHOD(int32_t, SendCustomData, (const AAFwk::WantParams& data), (override));
    MOCK_METHOD(int32_t, Start, (const AVQueueItem& avQueueItem), (override));
    MOCK_METHOD(int32_t, Prepare, (const AVQueueItem& avQueueItem), (override));
    MOCK_METHOD(int32_t, RegisterCallback, (const std::shared_ptr<AVCastControllerCallback>& callback), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t& duration), (override));
    MOCK_METHOD(int32_t, GetCastAVPlaybackState, (AVPlaybackState& avPlaybackState), (override));
    MOCK_METHOD(int32_t, GetSupportedDecoders, (std::vector<std::string>& decoderTypes), (override));
    MOCK_METHOD(int32_t, GetRecommendedResolutionLevel, (std::string& decoderType, ResolutionLevel& resolutionLevel),
        (override));
    MOCK_METHOD(int32_t, GetSupportedHdrCapabilities, (std::vector<HDRFormat>& hdrFormats), (override));
    MOCK_METHOD(int32_t, GetSupportedPlaySpeeds, (std::vector<float>& playSpeeds), (override));
    MOCK_METHOD(int32_t, GetCurrentItem, (AVQueueItem& currentItem), (override));
    MOCK_METHOD(int32_t, GetValidCommands, (std::vector<int32_t>& cmds), (override));
    MOCK_METHOD(int32_t, SetDisplaySurface, (std::string& surfaceId), (override));
    MOCK_METHOD(int32_t, SetCastPlaybackFilter, (const AVPlaybackState::PlaybackStateMaskType& filter), (override));
    MOCK_METHOD(int32_t, ProcessMediaKeyResponse, (const std::string& assetId, const std::vector<uint8_t>& response),
    (override));
    MOCK_METHOD(int32_t, AddAvailableCommand, (const int32_t cmd), (override));
    MOCK_METHOD(int32_t, RemoveAvailableCommand, (const int32_t cmd), (override));
    MOCK_METHOD(int32_t, Destroy, (), (override));
};

/**
 * @tc.name: OH_AVCastController_SetAVCastController_001
 * @tc.desc: SetAVCastController from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SetAVCastController_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastController> castControllerMock = nullptr;

    bool result = avCastController.SetAVCastController(castControllerMock);
    EXPECT_EQ(result, false);

    castControllerMock = std::make_shared<AVCastControllerMock>();
    result = avCastController.SetAVCastController(castControllerMock);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: OH_AVCastController_Destroy_001
 * @tc.desc: Destroy from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_Destroy_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);

    AVSession_ErrCode result = avCastController.Destroy();
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    EXPECT_CALL(*castControllerMock, Destroy()).WillOnce(Return(0));
    result = avCastController.Destroy();
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_GetPlaybackState_001
 * @tc.desc: GetPlaybackState from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_GetPlaybackState_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    AVPlaybackState dummyState;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    OH_AVSession_AVPlaybackState *state = nullptr;
    ASSERT_NE(castControllerMock, nullptr);

    AVSession_ErrCode result = avCastController.GetPlaybackState(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    EXPECT_CALL(*castControllerMock, GetCastAVPlaybackState(_))
        .WillOnce(DoAll(SetArgReferee<0>(dummyState), Return(AV_SESSION_ERR_SERVICE_EXCEPTION)))
        .WillRepeatedly(DoAll(SetArgReferee<0>(dummyState), Return(0)));

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.GetPlaybackState(&state);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    avCastController.ohAVSessionPlaybackState_ = nullptr;
    result = avCastController.GetPlaybackState(&state);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.InitSharedPtrMember();
    result = avCastController.GetPlaybackState(&state);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterPlaybackStateChangedCallback_001
 * @tc.desc: RegisterPlaybackStateChangedCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterPlaybackStateChangedCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    int32_t filter = 1;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);

    AVSession_ErrCode result = avCastController.RegisterPlaybackStateChangedCallback(filter, nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    EXPECT_CALL(*castControllerMock, SetCastPlaybackFilter(_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*castControllerMock, AddAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));

    result = avCastController.RegisterPlaybackStateChangedCallback(filter, nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlaybackStateChangedCallback(filter, nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlaybackStateChangedCallback(filter, nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterPlaybackStateChangedCallback_001
 * @tc.desc: UnregisterPlaybackStateChangedCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterPlaybackStateChangedCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);

    AVSession_ErrCode result = avCastController.UnregisterPlaybackStateChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.UnregisterPlaybackStateChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    EXPECT_CALL(*castControllerMock, RemoveAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    avCastController.CheckAndRegister();

    result = avCastController.UnregisterPlaybackStateChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.UnregisterPlaybackStateChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterMediaItemChangedCallback_001
 * @tc.desc: RegisterMediaItemChangedCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterMediaItemChangedCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    
    avCastController.avCastController_ = castControllerMock;
    AVSession_ErrCode result = avCastController.RegisterMediaItemChangedCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterMediaItemChangedCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterMediaItemChangedCallback_001
 * @tc.desc: UnregisterMediaItemChangedCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterMediaItemChangedCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    AVSession_ErrCode result = avCastController.UnregisterMediaItemChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.ohAVCastControllerCallbackImpl_ = std::make_shared<OHAVCastControllerCallbackImpl>();
    result = avCastController.UnregisterMediaItemChangedCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterPlayNextCallback_001
 * @tc.desc: RegisterPlayNextCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterPlayNextCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    EXPECT_CALL(*castControllerMock, AddAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.RegisterPlayNextCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.RegisterPlayNextCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlayNextCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlayNextCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterPlayNextCallback_001
 * @tc.desc: UnregisterPlayNextCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterPlayNextCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    EXPECT_CALL(*castControllerMock, RemoveAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.UnregisterPlayNextCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.UnregisterPlayNextCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.CheckAndRegister();
    result = avCastController.UnregisterPlayNextCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.UnregisterPlayNextCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterPlayPreviousCallback_001
 * @tc.desc: RegisterPlayPreviousCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterPlayPreviousCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    EXPECT_CALL(*castControllerMock, AddAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.RegisterPlayPreviousCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.RegisterPlayPreviousCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlayPreviousCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterPlayPreviousCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterPlayPreviousCallback_001
 * @tc.desc: UnregisterPlayPreviousCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterPlayPreviousCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    EXPECT_CALL(*castControllerMock, RemoveAvailableCommand(_))
        .WillOnce(Return(AV_SESSION_ERR_SERVICE_EXCEPTION))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.UnregisterPlayPreviousCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.UnregisterPlayPreviousCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.CheckAndRegister();
    result = avCastController.UnregisterPlayPreviousCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.UnregisterPlayPreviousCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterSeekDoneCallback_001
 * @tc.desc: RegisterSeekDoneCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterSeekDoneCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    avCastController.avCastController_ = castControllerMock;

    AVSession_ErrCode result = avCastController.RegisterSeekDoneCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterSeekDoneCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterSeekDoneCallback_001
 * @tc.desc: UnregisterSeekDoneCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterSeekDoneCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;

    AVSession_ErrCode result = avCastController.UnregisterSeekDoneCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.ohAVCastControllerCallbackImpl_ = std::make_shared<OHAVCastControllerCallbackImpl>();
    result = avCastController.UnregisterSeekDoneCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterEndOfStreamCallback_001
 * @tc.desc: RegisterEndOfStreamCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterEndOfStreamCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    avCastController.avCastController_ = castControllerMock;

    AVSession_ErrCode result = avCastController.RegisterEndOfStreamCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterEndOfStreamCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterEndOfStreamCallback_001
 * @tc.desc: UnregisterEndOfStreamCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterEndOfStreamCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;

    AVSession_ErrCode result = avCastController.UnregisterEndOfStreamCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.ohAVCastControllerCallbackImpl_ = std::make_shared<OHAVCastControllerCallbackImpl>();
    result = avCastController.UnregisterEndOfStreamCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_RegisterErrorCallback_001
 * @tc.desc: RegisterErrorCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_RegisterErrorCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(AV_SESSION_ERR_SERVICE_EXCEPTION));
    avCastController.avCastController_ = castControllerMock;

    AVSession_ErrCode result = avCastController.RegisterErrorCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.RegisterErrorCallback(nullptr, nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_UnregisterErrorCallback_001
 * @tc.desc: UnregisterErrorCallback from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_UnregisterErrorCallback_001, TestSize.Level0)
{
    OHAVCastController avCastController;

    AVSession_ErrCode result = avCastController.UnregisterErrorCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    avCastController.ohAVCastControllerCallbackImpl_ = std::make_shared<OHAVCastControllerCallbackImpl>();
    result = avCastController.UnregisterErrorCallback(nullptr);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_SendCommonCommand_001
 * @tc.desc: SendCommonCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendCommonCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));

    AVSession_AVCastControlCommandType type = CAST_CONTROL_CMD_PLAY;
    AVSession_ErrCode result = avCastController.SendCommonCommand(&type);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.SendCommonCommand(&type);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    type = static_cast<AVSession_AVCastControlCommandType>(-1);
    result = avCastController.SendCommonCommand(&type);
    EXPECT_EQ(result, AV_SESSION_ERR_CODE_COMMAND_INVALID);
}

/**
 * @tc.name: OH_AVCastController_SendSeekCommand_001
 * @tc.desc: SendSeekCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendSeekCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.SendSeekCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.SendSeekCommand(-1);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.SendSeekCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_SendFastForwardCommand_001
 * @tc.desc: SendFastForwardCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendFastForwardCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.SendFastForwardCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.SendFastForwardCommand(-1);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.SendFastForwardCommand(1);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_SendRewindCommand_001
 * @tc.desc: SendRewindCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendRewindCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.SendRewindCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.SendRewindCommand(-1);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.SendRewindCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_SendSetSpeedCommand_001
 * @tc.desc: SendSetSpeedCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendSetSpeedCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));
    AVSession_PlaybackSpeed speed = SPEED_FORWARD_1_00_X;

    AVSession_ErrCode result = avCastController.SendSetSpeedCommand(speed);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    speed = static_cast<AVSession_PlaybackSpeed>(-1);
    result = avCastController.SendSetSpeedCommand(speed);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    speed = SPEED_FORWARD_1_00_X;
    result = avCastController.SendSetSpeedCommand(speed);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_SendVolumeCommand_001
 * @tc.desc: SendVolumeCommand from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_SendVolumeCommand_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, SendControlCommand(_))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.SendVolumeCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.SendVolumeCommand(0);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_IsSameAVQueueItem_001
 * @tc.desc: IsSameAVQueueItem from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_IsSameAVQueueItem_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    AVQueueItem avQueueItem;
    auto description = std::make_shared<AVMediaDescription>();

    avCastController.avQueueItem_.SetDescription(nullptr);
    avCastController.UpdateAVQueueItem(avQueueItem);
    avCastController.avQueueItem_.SetDescription(description);
    avQueueItem.SetDescription(nullptr);
    avCastController.UpdateAVQueueItem(avQueueItem);
    avQueueItem.SetDescription(description);
    avCastController.UpdateAVQueueItem(avQueueItem);

    bool result = avCastController.IsSameAVQueueItem(avQueueItem);
    EXPECT_EQ(result, true);

    avQueueItem.SetDescription(nullptr);
    result = avCastController.IsSameAVQueueItem(avQueueItem);
    EXPECT_EQ(result, false);

    avCastController.avQueueItem_.SetDescription(nullptr);
    result = avCastController.IsSameAVQueueItem(avQueueItem);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: OH_AVCastController_Prepare_001
 * @tc.desc: Prepare from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_Prepare_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, Prepare(_))
        .WillRepeatedly(Return(0));
    OH_AVSession_AVQueueItem avqueueItem {};
    auto description = std::make_shared<AVMediaDescription>();
    ASSERT_NE(description, nullptr);
    description->SetMediaId("111");
    avqueueItem.description = (OH_AVSession_AVMediaDescription*)(description.get());

    avCastController.avCastController_ = castControllerMock;
    AVSession_ErrCode result = avCastController.Prepare(&avqueueItem);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    result = avCastController.Prepare(&avqueueItem);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_Start_001
 * @tc.desc: Start from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_Start_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, Start(_))
        .WillRepeatedly(Return(0));
    OH_AVSession_AVQueueItem avqueueItem {};
    auto description = std::make_shared<AVMediaDescription>();
    ASSERT_NE(description, nullptr);
    description->SetMediaId("111");
    avqueueItem.description = (OH_AVSession_AVMediaDescription*)(description.get());

    AVSession_ErrCode result = avCastController.Start(&avqueueItem);
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.Start(&avqueueItem);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_CheckAndRegister_001
 * @tc.desc: CheckAndRegister from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_CheckAndRegister_001, TestSize.Level0)
{
    OHAVCastController avCastController;
    std::shared_ptr<AVCastControllerMock> castControllerMock = std::make_shared<AVCastControllerMock>();
    ASSERT_NE(castControllerMock, nullptr);
    EXPECT_CALL(*castControllerMock, RegisterCallback(_))
        .WillRepeatedly(Return(0));

    AVSession_ErrCode result = avCastController.CheckAndRegister();
    EXPECT_EQ(result, AV_SESSION_ERR_INVALID_PARAMETER);

    avCastController.avCastController_ = castControllerMock;
    result = avCastController.CheckAndRegister();
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);

    result = avCastController.CheckAndRegister();
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVCastController_GetEncodeErrcode_001
 * @tc.desc: GetEncodeErrcode from the class of ohavcastcontroller
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVCastControllerTest, OH_AVCastController_GetEncodeErrcode_001, TestSize.Level0)
{
    OHAVCastController avCastController;

    AVSession_ErrCode result = avCastController.GetEncodeErrcode(-1);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);

    result = avCastController.GetEncodeErrcode(0);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

} // namespace OHOS::AVSession