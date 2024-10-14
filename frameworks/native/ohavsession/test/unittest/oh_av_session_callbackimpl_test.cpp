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
#include "native_avsession.h"
#include "OHAVSessionCallbackImpl.h"
#include "avsession_log.h"
#include "avsession_manager.h"

using namespace testing::ext;

namespace OHOS::AVSession {
static OHAVSessionCallbackImpl g_ohAVSessionCallbackImpl;

class OHAVSessionCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHAVSessionCallbackImplTest::SetUpTestCase(void)
{
}

void OHAVSessionCallbackImplTest::TearDownTestCase(void)
{
}

void OHAVSessionCallbackImplTest::SetUp()
{
}

void OHAVSessionCallbackImplTest::TearDown()
{
}

/**
 * @tc.name: UnSetPlayCallback001
 * @tc.desc: test UnSetPlayCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, UnSetPlayCallback001, TestSize.Level1)
{
    SLOGI("UnSetPlayCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "UnSetPlayCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.SetPlayCallback(avsession, command, callback, (void *)(&userData));
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.UnSetPlayCallback(
        avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("UnSetPlayCallback001 End");
}

/**
 * @tc.name: SetPauseCallback001
 * @tc.desc: test SetPauseCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPauseCallback001, TestSize.Level1)
{
    SLOGI("SetPauseCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPauseCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPauseCallback(
        avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPauseCallback001 End");
}

/**
 * @tc.name: SetPauseCallback002
 * @tc.desc: test SetPauseCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPauseCallback002, TestSize.Level1)
{
    SLOGI("SetPauseCallback002 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPauseCallback002", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPauseCallback(
        avsession, command, callback, (void *)(&userData));
    g_ohAVSessionCallbackImpl.SetPauseCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPauseCallback002 End");
}

/**
 * @tc.name: UnSetPauseCallback001
 * @tc.desc: test UnSetPauseCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, UnSetPauseCallback001, TestSize.Level1)
{
    SLOGI("UnSetPauseCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "UnSetPauseCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.SetPauseCallback(avsession, command, callback, (void *)(&userData));
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.UnSetPauseCallback(
        avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("UnSetPauseCallback001 End");
}

/**
 * @tc.name: SetStopCallback001
 * @tc.desc: test SetStopCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetStopCallback001, TestSize.Level1)
{
    SLOGI("SetStopCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetStopCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetStopCallback(
        avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetStopCallback001 End");
}

/**
 * @tc.name: SetStopCallback002
 * @tc.desc: test SetStopCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetStopCallback002, TestSize.Level1)
{
    SLOGI("SetStopCallback002 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetStopCallback002", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetStopCallback(
        avsession, command, callback, (void *)(&userData));
    g_ohAVSessionCallbackImpl.SetStopCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetStopCallback002 End");
}

/**
 * @tc.name: SetPlayNextCallback001
 * @tc.desc: test SetPlayNextCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayNextCallback001, TestSize.Level1)
{
    SLOGI("SetPlayNextCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPlayNextCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayNextCallback(
        avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPlayNextCallback001 End");
}

/**
 * @tc.name: SetPlayNextCallback002
 * @tc.desc: test SetPlayNextCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayNextCallback002, TestSize.Level1)
{
    SLOGI("SetPlayNextCallback002 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPlayNextCallback002", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayNextCallback(
        avsession, command, callback, (void *)(&userData));
    g_ohAVSessionCallbackImpl.SetPlayNextCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPlayNextCallback002 End");
}

/**
 * @tc.name: SetPlayPreviousCallback001
 * @tc.desc: test SetPlayPreviousCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayPreviousCallback001, TestSize.Level1)
{
    SLOGI("SetPlayPreviousCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPlayPreviousCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayPreviousCallback(
        avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPlayPreviousCallback001 End");
}

/**
 * @tc.name: SetPlayPreviousCallback002
 * @tc.desc: test SetPlayPreviousCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayPreviousCallback002, TestSize.Level1)
{
    SLOGI("SetPlayPreviousCallback002 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPlayPreviousCallback002", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayPreviousCallback(
        avsession, command, callback, (void *)(&userData));
    g_ohAVSessionCallbackImpl.SetPlayPreviousCallback(avsession, command, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPlayPreviousCallback002 End");
}

}