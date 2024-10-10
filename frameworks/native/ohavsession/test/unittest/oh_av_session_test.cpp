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
#include "OHAVSession.h"
#include "OHAVMetadataBuilder.h"
#include "native_avmetadata.h"
#include "avmeta_data.h"

using namespace testing::ext;

namespace OHOS::AVSession {

class OHAVSessionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHAVSessionTest::SetUpTestCase(void)
{
}

void OHAVSessionTest::TearDownTestCase(void)
{
}

void OHAVSessionTest::SetUp()
{
}

void OHAVSessionTest::TearDown()
{
}

/**
 * @tc.name: OH_AVSession_Create_001
 * @tc.desc: Create from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_Create_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_Create_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_Destory_001
 * @tc.desc: Destory from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_Destory_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_Destory_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_Activate_001
 * @tc.desc: Activate from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_Activate_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_Activate_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Activate(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_Deactivate_001
 * @tc.desc: Deactivate from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_Deactivate_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_Deactivate_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Deactivate(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_GetSessionType_001
 * @tc.desc: GetSessionType from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_GetSessionType_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_GetSessionType_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_Type sessionType;
    ret = OH_AVSession_GetSessionType(avsession, &sessionType);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    EXPECT_EQ(sessionType, SESSION_TYPE_AUDIO);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_GetSessionId_001
 * @tc.desc: GetSessionId from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_GetSessionId_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_GetSessionId_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    const char* sessionId;
    ret = OH_AVSession_GetSessionId(avsession, &sessionId);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_SetAVMetadata_001
 * @tc.desc: SetAVMetadata from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetAVMetadata_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    const uint64_t DURATION = 40000;
    const int32_t TAGS = 1;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_SetAVMetadata_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVMetadataBuilder *builder;
    OH_AVMetadata *ohMetaData;
    AVMetadata_Result res;
    res = OH_AVMetadataBuilder_Create(&builder);
    EXPECT_EQ(res, AVMETADATA_SUCCESS);
    OH_AVMetadataBuilder_SetTitle(builder, "UNIT TEST");
    OH_AVMetadataBuilder_SetArtist(builder, "Anonymous artist");
    OH_AVMetadataBuilder_SetAuthor(builder, "Anonymous author");
    OH_AVMetadataBuilder_SetAlbum(builder, "Anonymous album");
    OH_AVMetadataBuilder_SetWriter(builder, "Anonymous writer");
    OH_AVMetadataBuilder_SetComposer(builder, "Anonymous composer");
    OH_AVMetadataBuilder_SetDuration(builder, DURATION);
    OH_AVMetadataBuilder_SetMediaImageUri(builder, "https://xxx.xxx.xx");
    OH_AVMetadataBuilder_SetSubtitle(builder, "fac");
    OH_AVMetadataBuilder_SetDescription(builder, "For somebody");
    OH_AVMetadataBuilder_SetLyric(builder, "balabala");
    OH_AVMetadataBuilder_SetAssetId(builder, "999");
    OH_AVMetadataBuilder_SetSkipIntervals(builder, SECONDS_30);
    OH_AVMetadataBuilder_SetDisplayTags(builder, TAGS);
    OH_AVMetadataBuilder_GenerateAVMetadata(builder, &ohMetaData);

    ret = OH_AVSession_SetAVMetadata(avsession, ohMetaData);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVMetadata_Destroy(ohMetaData);
    OH_AVMetadataBuilder_Destroy(builder);
}

/**
 * @tc.name: OH_AVSession_SetPlaybackState_001
 * @tc.desc: SetPlaybackState from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetPlaybackState_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_SetPlaybackState_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_PlaybackState state = PLAYBACK_STATE_PREPARING;
    ret = OH_AVSession_SetPlaybackState(avsession, state);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_SetPlaybackPosition_001
 * @tc.desc: SetPlaybackPosition from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetPlaybackPosition_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_SetPlaybackPosition_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_PlaybackPosition* playbackPosition = new AVSession_PlaybackPosition;
    playbackPosition->elapsedTime = 1;
    playbackPosition->updateTime = 2;
    ret = OH_AVSession_SetPlaybackPosition(avsession, playbackPosition);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_SetFavorite_001
 * @tc.desc: SetFavorite from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetFavorite_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    bool isFavorite = true;
    ret = OH_AVSession_SetFavorite(avsession, isFavorite);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_SetLoopMode_001
 * @tc.desc: SetLoopMode from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetLoopMode_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_LoopMode loopMode = LOOP_MODE_SINGLE;
    ret = OH_AVSession_SetLoopMode(avsession, loopMode);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_001
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterCommandCallback_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_002
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_002, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_RegisterCommandCallback_002",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PAUSE;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_003
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_003, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_RegisterCommandCallback_003",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_STOP;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_004
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_004, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_RegisterCommandCallback_004",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_NEXT;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_005
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_005, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_RegisterCommandCallback_005",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_PREVIOUS;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterCommandCallback_006
 * @tc.desc: RegisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_006, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_RegisterCommandCallback_006",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_INVALID;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterCommandCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_CODE_COMMAND_INVALID);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_001
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "UnregisterCommandCallback_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_002
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_002, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_UnregisterCommandCallback_002",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PAUSE;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_003
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_003, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_UnregisterCommandCallback_003",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_STOP;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_004
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_004, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_UnregisterCommandCallback_004",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_NEXT;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_005
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_005, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_UnregisterCommandCallback_005",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_PREVIOUS;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterCommandCallback_006
 * @tc.desc: UnregisterCommandCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_006, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_UnregisterCommandCallback_006",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_ControlCommand command = CONTROL_CMD_INVALID;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_UnregisterCommandCallback(avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_CODE_COMMAND_INVALID);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterForwardCallback_001
 * @tc.desc: RegisterForwardCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterForwardCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnFastForward callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterForwardCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterForwardCallback_001
 * @tc.desc: UnregisterForwardCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterForwardCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnFastForward callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterForwardCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterForwardCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterRewindCallback_001
 * @tc.desc: RegisterRewindCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterRewindCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnRewind callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterRewindCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterRewindCallback_001
 * @tc.desc: UnregisterRewindCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterRewindCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnRewind callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterRewindCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterRewindCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterSeekCallback_001
 * @tc.desc: RegisterSeekCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterSeekCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnSeek callback = [](OH_AVSession* session, uint64_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterSeekCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterSeekCallback_001
 * @tc.desc: UnregisterSeekCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterSeekCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnSeek callback = [](OH_AVSession* session, uint64_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterSeekCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterSeekCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterSetLoopModeCallback_001
 * @tc.desc: RegisterSetLoopModeCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterSetLoopModeCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnSetLoopMode callback = [](OH_AVSession* session, AVSession_LoopMode curLoopMode,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterSetLoopModeCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterSetLoopModeCallback_001
 * @tc.desc: UnregisterSetLoopModeCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterSetLoopModeCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnSetLoopMode callback = [](OH_AVSession* session, AVSession_LoopMode curLoopMode,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterSetLoopModeCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterSetLoopModeCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_RegisterToggleFavoriteCallback_001
 * @tc.desc: RegisterToggleFavoriteCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_RegisterToggleFavoriteCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnToggleFavorite callback = [](OH_AVSession* session, const char* assetId,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterToggleFavoriteCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterToggleFavoriteCallback_001
 * @tc.desc: Unregister Toggle Favorite Callback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterToggleFavoriteCallback_001, TestSize.Level1)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OnToggleFavorite callback = [](OH_AVSession* session, const char* assetId,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    ret = OH_AVSession_RegisterToggleFavoriteCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterToggleFavoriteCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}
}