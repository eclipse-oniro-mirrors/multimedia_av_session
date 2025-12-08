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
#include "OHAVSession.h"
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
HWTEST_F(OHAVSessionCallbackImplTest, UnSetPlayCallback001, TestSize.Level0)
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
    ret = OH_AVSession_Destroy(avsession);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("UnSetPlayCallback001 End");
}

/**
 * @tc.name: SetPauseCallback001
 * @tc.desc: test SetPauseCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPauseCallback001, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetPauseCallback002, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, UnSetPauseCallback001, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetStopCallback001, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetStopCallback002, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayNextCallback001, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayNextCallback002, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayPreviousCallback001, TestSize.Level0)
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
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayPreviousCallback002, TestSize.Level0)
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

/**
 * @tc.name: SetPlayCallback001
 * @tc.desc: test SetPlayCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, SetPlayCallback001, TestSize.Level0)
{
    SLOGI("SetPlayCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "SetPlayCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    g_ohAVSessionCallbackImpl.SetPlayCallback(avsession, command, callback, (void *)(&userData));
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.UnSetPlayCallback(
        avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("SetPlayCallback001 End");
}

/**
 * @tc.name: RegisterForwardCallback001
 * @tc.desc: test RegisterForwardCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterForwardCallback001, TestSize.Level0)
{
    SLOGI("RegisterForwardCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterForwardCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    OH_AVSessionCallback_OnFastForward callback = [](OH_AVSession* session, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterForwardCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("RegisterForwardCallback001 End");
}

/**
 * @tc.name: RegisterSeekCallback001
 * @tc.desc: test RegisterSeekCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterSeekCallback001, TestSize.Level0)
{
    SLOGI("RegisterSeekCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterSeekCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    OH_AVSessionCallback_OnSeek callback = [](OH_AVSession* session,  uint64_t seekTime,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterSeekCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("RegisterSeekCallback001 End");
}

/**
 * @tc.name: RegisterSetLoopModeCallback001
 * @tc.desc: test RegisterSetLoopModeCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterSetLoopModeCallback001, TestSize.Level0)
{
    SLOGI("RegisterSetLoopModeCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterSetLoopModeCallback", "com.xxx.hmxx", "ndkxx", &avsession);
    OH_AVSessionCallback_OnSetLoopMode callback = [](OH_AVSession* session, AVSession_LoopMode curLoopMode,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterSetLoopModeCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("RegisterSetLoopModeCallback001 End");
}

/**
 * @tc.name: RegisterToggleFavoriteCallback001
 * @tc.desc: test RegisterToggleFavoriteCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterToggleFavoriteCallback001, TestSize.Level0)
{
    SLOGI("RegisterToggleFavoriteCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterToggleFavoriteCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    OH_AVSessionCallback_OnToggleFavorite callback = [](OH_AVSession* session, const char* assetId,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterToggleFavoriteCallback(avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("RegisterToggleFavoriteCallback001 End");
}

/**
 * @tc.name: RegisterForwardCallback002
 * @tc.desc: have registered RegisterForwardCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterForwardCallback002, TestSize.Level0)
{
    SLOGI("RegisterForwardCallback002 Begin");
    auto avsession = std::make_shared<OHAVSession>();
    OH_AVSession* oh_avsession = reinterpret_cast<OH_AVSession*>(avsession.get());
    EXPECT_TRUE(oh_avsession != nullptr);

    OH_AVSessionCallback_OnFastForward callback = [](OH_AVSession* oh_avsession, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = oh_avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterForwardCallback(oh_avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);

    auto it = std::find_if (g_ohAVSessionCallbackImpl.forwardCallbacks_.begin(),
        g_ohAVSessionCallbackImpl.forwardCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnFastForward, void*> &element) {
            return element.first == callback; });
    EXPECT_TRUE (it != g_ohAVSessionCallbackImpl.forwardCallbacks_.end());
    SLOGI("RegisterForwardCallback002 End");
}

/**
 * @tc.name: RegisterRewindCallback002
 * @tc.desc: have registered RegisterRewindCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterRewindCallback002, TestSize.Level0)
{
    SLOGI("RegisterRewindCallback002 Begin");
    auto avsession = std::make_shared<OHAVSession>();
    OH_AVSession* oh_avsession = reinterpret_cast<OH_AVSession*>(avsession.get());
    EXPECT_TRUE(oh_avsession != nullptr);

    OH_AVSessionCallback_OnRewind callback = [](OH_AVSession* oh_avsession, uint32_t seekTime,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = oh_avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterRewindCallback(oh_avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);

    auto it = std::find_if (g_ohAVSessionCallbackImpl.rewindCallbacks_.begin(),
        g_ohAVSessionCallbackImpl.rewindCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnRewind, void*> &element) {
            return element.first == callback; });
    EXPECT_TRUE (it != g_ohAVSessionCallbackImpl.rewindCallbacks_.end());
    SLOGI("RegisterRewindCallback002 End");
}

/**
 * @tc.name: RegisterSeekCallback002
 * @tc.desc: have registered RegisterSeekCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterSeekCallback002, TestSize.Level0)
{
    SLOGI("RegisterSeekCallback002 Begin");
    auto avsession = std::make_shared<OHAVSession>();
    OH_AVSession* oh_avsession = reinterpret_cast<OH_AVSession*>(avsession.get());
    EXPECT_TRUE(oh_avsession != nullptr);

    OH_AVSessionCallback_OnSeek callback = [](OH_AVSession* oh_avsession, uint64_t seekTime,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = oh_avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterSeekCallback(oh_avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);

    auto it = std::find_if (g_ohAVSessionCallbackImpl.seekCallbacks_.begin(),
        g_ohAVSessionCallbackImpl.seekCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSeek, void*> &element) {
            return element.first == callback; });
    EXPECT_TRUE (it != g_ohAVSessionCallbackImpl.seekCallbacks_.end());
    SLOGI("RegisterSeekCallback002 End");
}

/**
 * @tc.name: RegisterSetLoopModeCallback002
 * @tc.desc: have registered RegisterSetLoopModeCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterSetLoopModeCallback002, TestSize.Level0)
{
    SLOGI("RegisterSetLoopModeCallback002 Begin");
    auto avsession = std::make_shared<OHAVSession>();
    OH_AVSession* oh_avsession = reinterpret_cast<OH_AVSession*>(avsession.get());
    EXPECT_TRUE(oh_avsession != nullptr);

    OH_AVSessionCallback_OnSetLoopMode callback = [](OH_AVSession* session,
        AVSession_LoopMode curLoopMode, void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = oh_avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterSetLoopModeCallback(oh_avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);

    auto it = std::find_if (g_ohAVSessionCallbackImpl.setLoopModeCallbacks_.begin(),
        g_ohAVSessionCallbackImpl.setLoopModeCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSetLoopMode, void*> &element) {
            return element.first == callback; });
    EXPECT_TRUE (it != g_ohAVSessionCallbackImpl.setLoopModeCallbacks_.end());
    SLOGI("RegisterSetLoopModeCallback002 End");
}

/**
 * @tc.name: RegisterToggleFavoriteCallback002
 * @tc.desc: have registered RegisterToggleFavoriteCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterToggleFavoriteCallback002, TestSize.Level0)
{
    SLOGI("RegisterToggleFavoriteCallback002 Begin");
    auto avsession = std::make_shared<OHAVSession>();
    OH_AVSession* oh_avsession = reinterpret_cast<OH_AVSession*>(avsession.get());
    EXPECT_TRUE(oh_avsession != nullptr);

    OH_AVSessionCallback_OnToggleFavorite callback = [](OH_AVSession* session,
        const char* assetId, void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    g_ohAVSessionCallbackImpl.avsession_ = oh_avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterToggleFavoriteCallback(oh_avsession, callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);

    auto it = std::find_if (g_ohAVSessionCallbackImpl.toggleFavoriteCallbacks_.begin(),
        g_ohAVSessionCallbackImpl.toggleFavoriteCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnToggleFavorite, void*> &element) {
            return element.first == callback; });
    EXPECT_TRUE (it != g_ohAVSessionCallbackImpl.toggleFavoriteCallbacks_.end());
    SLOGI("RegisterToggleFavoriteCallback002 End");
}

/**
 * @tc.name: OnSetTargetLoopMode001
 * @tc.desc: have registered RegisterToggleFavoriteCallback
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, OnSetTargetLoopMode001, TestSize.Level1)
{
    SLOGI("OnSetTargetLoopMode001 Begin");
    std::string assetId = "assetId";
    g_ohAVSessionCallbackImpl.OnPlayWithAssetId(assetId);
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "UnSetPlayCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    AVSession_LoopMode loopMode = LOOP_MODE_SINGLE;
    g_ohAVSessionCallbackImpl.OnSetTargetLoopMode(loopMode);
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayCallback(avsession, command,
        callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = g_ohAVSessionCallbackImpl.UnSetPlayCallback(
        avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("OnSetTargetLoopMode001 End");
}

/**
 * @tc.name: OnPlayWithAssetId001
 * @tc.desc: have registered OnPlayWithAssetId
 * @tc.type: FUNC
 * @tc.require: AR000H31JO
 */
HWTEST_F(OHAVSessionCallbackImplTest, OnPlayWithAssetId001, TestSize.Level0)
{
    SLOGI("OnPlayWithAssetId001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "UnSetPlayCallback001", "com.xxx.hmxx", "ndkxx", &avsession);
    AVSession_ControlCommand command = CONTROL_CMD_PLAY;
    OH_AVSessionCallback_OnCommand callback = [](OH_AVSession* session, AVSession_ControlCommand command,
        void* userData) -> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    int userData = 1;
    std::string assetId = "assetId";
    g_ohAVSessionCallbackImpl.OnPlayWithAssetId(assetId);
    AVSession_ErrCode ret = g_ohAVSessionCallbackImpl.SetPlayCallback(avsession, command,
        callback, (void *)(&userData));
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    ret = g_ohAVSessionCallbackImpl.UnSetPlayCallback(
        avsession, command, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("OnPlayWithAssetId001 End");
}

/**
 * @tc.name: RegisterOutputDeviceChangeCallback001
 * @tc.desc: test RegisterOutputDeviceChangeCallback
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVSessionCallbackImplTest, RegisterOutputDeviceChangeCallback001, TestSize.Level0)
{
    SLOGI("RegisterOutputDeviceChangeCallback001 Begin");
    OH_AVSession* avsession = nullptr;
    OH_AVSession_Create(SESSION_TYPE_AUDIO, "RegisterOutputDeviceChangeCallback001",
        "com.xxx.hmxx", "ndkxx", &avsession);
    OH_AVSessionCallback_OutputDeviceChange callback = [](OH_AVSession* session,
        AVSession_ConnectionState state, AVSession_OutputDeviceInfo* outputDeviceInfo)-> AVSessionCallback_Result {
        return AVSESSION_CALLBACK_RESULT_SUCCESS;
    };
    g_ohAVSessionCallbackImpl.avsession_ = avsession;
    auto ret = g_ohAVSessionCallbackImpl.RegisterOutputDeviceChangeCallback(avsession, callback);
    EXPECT_EQ(ret, AV_SESSION_ERR_SUCCESS);
    SLOGI("RegisterOutputDeviceChangeCallback001 End");
}
} //OHOS::AVSession
