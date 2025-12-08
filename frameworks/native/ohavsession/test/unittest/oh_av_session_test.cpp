/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
HWTEST(OHAVSessionTest, OH_AVSession_Create_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_Destory_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_Activate_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_Deactivate_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_GetSessionType_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_GetSessionId_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_SetAVMetadata_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_SetPlaybackState_001, TestSize.Level0)
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
 * @tc.name: OH_AVSession_SetPlaybackState_002
 * @tc.desc: SetPlaybackState from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetPlaybackState_002, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "OH_AVSession_SetPlaybackState_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_PlaybackState state = PLAYBACK_STATE_MAX;
    ret = OH_AVSession_SetPlaybackState(avsession, state);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_SetPlaybackPosition_001
 * @tc.desc: SetPlaybackPosition from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
*/
HWTEST(OHAVSessionTest, OH_AVSession_SetPlaybackPosition_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_SetFavorite_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_SetLoopMode_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_002, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_003, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_004, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_005, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterCommandCallback_006, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_002, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_003, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_004, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_005, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterCommandCallback_006, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterForwardCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterForwardCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterRewindCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterRewindCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterSeekCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterSeekCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterSetLoopModeCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterSetLoopModeCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_RegisterToggleFavoriteCallback_001, TestSize.Level0)
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
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterToggleFavoriteCallback_001, TestSize.Level0)
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

/**
 * @tc.name: GetEncodeErrcode001
 * @tc.desc: Test GetEncodeErrcode with an error code that is not in the errcodes map.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, GetEncodeErrcode_001, TestSize.Level0)
{
    auto oHAVSession = std::make_shared<OHAVSession>();
    int32_t invalidErrorCode = 9999999;
    AVSession_ErrCode result = oHAVSession->GetEncodeErrcode(invalidErrorCode);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);
}

/**
 * @tc.name: OHAVSession_GetSessionId_001
 * @tc.desc: Test GetSessionId without entering the if branch by setting sessionId_ to a non-empty value.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_GetSessionId_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);

    const std::string preSetSessionId = "predefined_session_id";
    oHAVSession->sessionId_ = preSetSessionId;

    const std::string& sessionId = oHAVSession->GetSessionId();
    EXPECT_EQ(sessionId, preSetSessionId);
}

/**
 * @tc.name: RegisterCommandCallback001
 * @tc.desc: Test RegisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, RegisterCommandCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_INVALID;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode result = oHAVSession->RegisterCommandCallback(command, callback, (void *)(&userData));
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);
}

/**
 * @tc.name: RegisterCommandCallback002
 * @tc.desc: Test RegisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, RegisterCommandCallback_002, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->RegisterCommandCallback(command, callback, (void *)(&userData));
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback001
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int32_t code = 1;
    AVSession_ErrCode ret = oHAVSession->GetEncodeErrcode(code);
    EXPECT_EQ(ret, AV_SESSION_ERR_SERVICE_EXCEPTION);
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback002
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_002, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_PAUSE;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback003
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_003, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_STOP;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback004
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_004, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_NEXT;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback005
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_005, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY_PREVIOUS;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterCommandCallback006
 * @tc.desc: Test UnregisterCommandCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterCommandCallback_006, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_INVALID;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->UnregisterCommandCallback(command, callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);
}

/**
 * @tc.name: UnregisterForwardCallback001
 * @tc.desc: Test UnregisterForwardCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterForwardCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    OH_AVSessionCallback_OnFastForward callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->UnregisterForwardCallback(callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterRewindCallback001
 * @tc.desc: Test UnregisterRewindCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterRewindCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    OH_AVSessionCallback_OnRewind callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->UnregisterRewindCallback(callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterSeekCallback001
 * @tc.desc: Test UnregisterSeekCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterSeekCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    OH_AVSessionCallback_OnSeek callback = [](OH_AVSession* session, uint64_t seekTime,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->UnregisterSeekCallback(callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterSetLoopModeCallback
 * @tc.desc: Test UnregisterSetLoopModeCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterSetLoopModeCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    OH_AVSessionCallback_OnSetLoopMode callback = [](OH_AVSession* session, AVSession_LoopMode curLoopMode,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->UnregisterSetLoopModeCallback(callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: UnregisterToggleFavoriteCallback
 * @tc.desc: Test UnregisterToggleFavoriteCallback.
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, UnregisterToggleFavoriteCallback_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    OH_AVSessionCallback_OnToggleFavorite callback = [](OH_AVSession* session, const char* assetId,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->UnregisterToggleFavoriteCallback(callback);
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_GetSessionId_002
 * @tc.desc: Test GetSessionId when sessionId_ is empty
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_GetSessionId_002, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);

    oHAVSession->sessionId_ = "";

    const std::string& sessionId = oHAVSession->GetSessionId();
    EXPECT_TRUE(sessionId != "");
}

/**
 * @tc.name: RegisterCommandCallback_003
 * @tc.desc: send invalid command
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, RegisterCommandCallback_003, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = static_cast<AVSession_ControlCommand>(100);
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->RegisterCommandCallback(command, callback, (void *)(&userData));
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);
}

/**
 * @tc.name: RegisterCommandCallback_004
 * @tc.desc: send invalid command
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, RegisterCommandCallback_004, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    AVSession_ControlCommand command = CONTROL_CMD_INVALID;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->RegisterCommandCallback(command, callback, (void *)(&userData));
    EXPECT_EQ(result, AV_SESSION_ERR_SERVICE_EXCEPTION);
}

/**
 * @tc.name: CheckAndRegister_001
 * @tc.desc: have not registered callback
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, CheckAndRegister_001, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    oHAVSession->ohAVSessionCallbackImpl_ = nullptr;
    AVSession_ErrCode result = oHAVSession->CheckAndRegister();
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: CheckAndRegister_002
 * @tc.desc: have registered callback
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, CheckAndRegister_002, TestSize.Level0)
{
    AVSession_Type sessionType = SESSION_TYPE_VIDEO;
    const char* sessionTag = "1";
    const char* bundleName = "2";
    const char* abilityName = "3";
    auto oHAVSession = std::make_shared<OHAVSession>(sessionType, sessionTag, bundleName, abilityName);
    oHAVSession->ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
    AVSession_ErrCode result = oHAVSession->CheckAndRegister();
    EXPECT_EQ(result, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_StopCasting_001
 * @tc.desc: Test stopping casting when avcastController is not nullptr
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_StopCasting_001, TestSize.Level0)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_StopCasting(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
#else
    GTEST_SKIP() << "CASTPLUS_CAST_ENGINE_ENABLE is not defined.";
#endif
}

/**
 * @tc.name: OHAVSession_StopCasting_002
 * @tc.desc: Test stopping casting when avsession is nullptr
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_StopCasting_002, TestSize.Level0)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_StopCasting(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
#else
    GTEST_SKIP() << "CASTPLUS_CAST_ENGINE_ENABLE is not defined.";
#endif
}

/**
 * @tc.name: OHAVSession_SetRemoteCastEnabled_001
 * @tc.desc: Test setting remote cast enabled
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_SetRemoteCastEnabled_001, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    bool enabled = true;
    ret = OH_AVSession_SetRemoteCastEnabled(avsession, enabled);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_SetRemoteCastEnabled_002
 * @tc.desc: Test setting remote cast disabled
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_SetRemoteCastEnabled_002, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    bool enabled = false;
    ret = OH_AVSession_SetRemoteCastEnabled(avsession, enabled);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_GetOutputDevice_001
 * @tc.desc: Test getting output device
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_GetOutputDevice_001, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_OutputDeviceInfo* outputDevice = nullptr;
    ret = OH_AVSession_GetOutputDevice(avsession, &outputDevice);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_GetOutputDevice_002
 * @tc.desc: Test getting output device when avsession is nullptr
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_GetOutputDevice_002, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_OutputDeviceInfo* outputDevice = nullptr;
    AVSession_ErrCode ret = OH_AVSession_GetOutputDevice(avsession, &outputDevice);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
}

/**
 * @tc.name: OHAVSession_ReleaseOutputDevice_001
 * @tc.desc: Test releasing output device
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_ReleaseOutputDevice_001, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    AVSession_OutputDeviceInfo* outputDevice = nullptr;
    ret = OH_AVSession_GetOutputDevice(avsession, &outputDevice);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_ReleaseOutputDevice(avsession, outputDevice);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OHAVSession_ReleaseOutputDevice_002
 * @tc.desc: Test releasing output device when avsession is nullptr
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OHAVSession_ReleaseOutputDevice_002, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_OutputDeviceInfo* outputDevice = nullptr;
    AVSession_ErrCode ret = OH_AVSession_ReleaseOutputDevice(avsession, outputDevice);
    EXPECT_EQ(ret, AV_SESSION_ERR_INVALID_PARAMETER);
}

/**
 * @tc.name: OH_AVSession_RegisterOutputDeviceChangeCallback_001
 * @tc.desc: RegisterOutputDeviceChangeCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OH_AVSession_RegisterOutputDeviceChangeCallback_001, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OutputDeviceChange callback = [](OH_AVSession* session,
        AVSession_ConnectionState state, AVSession_OutputDeviceInfo* outputDeviceInfo) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_RegisterOutputDeviceChangeCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}

/**
 * @tc.name: OH_AVSession_UnregisterOutputDeviceChangeCallback_001
 * @tc.desc: UnregisterOutputDeviceChangeCallback from the class of ohavsession
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST(OHAVSessionTest, OH_AVSession_UnregisterOutputDeviceChangeCallback_001, TestSize.Level0)
{
    OH_AVSession* avsession = nullptr;
    AVSession_ErrCode ret = OH_AVSession_Create(SESSION_TYPE_AUDIO, "oh_av_session_test_001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    OH_AVSessionCallback_OutputDeviceChange callback = [](OH_AVSession* session,
        AVSession_ConnectionState state, AVSession_OutputDeviceInfo* outputDeviceInfo) -> AVSessionCallback_Result
    {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    ret = OH_AVSession_RegisterOutputDeviceChangeCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_UnregisterOutputDeviceChangeCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
}
}