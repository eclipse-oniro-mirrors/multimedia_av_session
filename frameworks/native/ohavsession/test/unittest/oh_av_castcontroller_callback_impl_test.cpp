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
#include "OHAVSession.h"
#include "OHAVCastControllerCallbackImpl.h"
#include "OHAVCastController.h"

using namespace testing::ext;
OHOS::AVSession::OHAVCastController g_ohavcastcontroller;
OH_AVCastController* g_avcastcontroller = nullptr;

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
    g_avcastcontroller = (OH_AVCastController*)(&g_ohavcastcontroller);
}

void OHAVCastControllerCallbackImplTest::TearDownTestCase(void)
{
    g_avcastcontroller = nullptr;
}

void OHAVCastControllerCallbackImplTest::SetUp()
{
}

void OHAVCastControllerCallbackImplTest::TearDown()
{
}

AVSessionCallback_Result CastControllerPlaybackStateChangedCallback(
    OH_AVCastController* avcastcontroller, OH_AVSession_AVPlaybackState* playbackState, void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerMediaItemChangeCallback(OH_AVCastController* avcastcontroller,
    OH_AVSession_AVQueueItem* avQueueItem, void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerPlayNextCallback(OH_AVCastController* avcastcontroller, void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerPlayPreviousCallback(OH_AVCastController* avcastcontroller, void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerSeekDoneCallback(OH_AVCastController* avcastcontroller,
    int32_t position, void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerEndOfStreamCallback(OH_AVCastController* avcastcontroller,
    void* userData)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

AVSessionCallback_Result CastControllerErrorCallback(OH_AVCastController* avcastcontroller,
    void* userData, AVSession_ErrCode error)
{
    bool *res = static_cast<bool*>(userData);
    if (res != nullptr) {
        *res = true;
    }
    return AVSessionCallback_Result::AVSESSION_CALLBACK_RESULT_SUCCESS;
}

/**
 * @tc.name: OnCastPlaybackStateChange001
 * @tc.desc: test OnCastPlaybackStateChange
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnCastPlaybackStateChange001, TestSize.Level0)
{
    AVPlaybackState state;
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnCastPlaybackStateChange(state);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playbackStateCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterPlaybackStateChangedCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnCastPlaybackStateChange(state);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playbackStateCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlaybackStateChangedCallback(g_avcastcontroller,
        CastControllerPlaybackStateChangedCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnCastPlaybackStateChange(state);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playbackStateCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlaybackStateChangedCallback(g_avcastcontroller,
        CastControllerPlaybackStateChangedCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnCastPlaybackStateChange(state);
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnMediaItemChange001
 * @tc.desc: test OnMediaItemChange
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnMediaItemChange001, TestSize.Level0)
{
    AVQueueItem avQueueItem;
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterMediaItemChangedCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.ohAVSessionAVQueueItem_ = nullptr;
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.InitSharedPtrMember();
    ohAVCastControllerCallbackImpl.ohAVMediaDescription_ = nullptr;
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.InitSharedPtrMember();
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), false);

    avQueueItem.SetDescription(std::make_shared<AVMediaDescription>());
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterMediaItemChangedCallback(g_avcastcontroller,
        CastControllerMediaItemChangeCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.mediaItemChangedCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterMediaItemChangedCallback(g_avcastcontroller,
        CastControllerMediaItemChangeCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnMediaItemChange(avQueueItem);
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnPlayNext001
 * @tc.desc: test OnPlayNext
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnPlayNext001, TestSize.Level0)
{
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnPlayNext();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playNextCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterPlayNextCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayNext();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playNextCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlayNextCallback(g_avcastcontroller,
        CastControllerPlayNextCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnPlayNext();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playNextCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlayNextCallback(g_avcastcontroller,
        CastControllerPlayNextCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayNext();
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnPlayPrevious001
 * @tc.desc: test OnPlayPrevious
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnPlayPrevious001, TestSize.Level0)
{
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnPlayPrevious();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playPreviousCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterPlayPreviousCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayPrevious();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playPreviousCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlayPreviousCallback(g_avcastcontroller,
        CastControllerPlayPreviousCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnPlayPrevious();
    EXPECT_EQ(ohAVCastControllerCallbackImpl.playPreviousCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterPlayPreviousCallback(g_avcastcontroller,
        CastControllerPlayPreviousCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayPrevious();
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnSeekDone001
 * @tc.desc: test OnSeekDone
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnSeekDone001, TestSize.Level0)
{
    int32_t seekNumber = 1;
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnSeekDone(seekNumber);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.seekDoneCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterSeekDoneCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnSeekDone(seekNumber);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.seekDoneCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterSeekDoneCallback(g_avcastcontroller,
        CastControllerSeekDoneCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnSeekDone(seekNumber);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.seekDoneCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterSeekDoneCallback(g_avcastcontroller,
        CastControllerSeekDoneCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnSeekDone(seekNumber);
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnPlayerError001
 * @tc.desc: test OnPlayerError
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnPlayerError001, TestSize.Level0)
{
    int32_t errorCode = 1;
    std::string errorMsg = "error";
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnPlayerError(errorCode, errorMsg);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.errorCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterErrorCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayerError(errorCode, errorMsg);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.errorCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterErrorCallback(g_avcastcontroller,
        CastControllerErrorCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnPlayerError(errorCode, errorMsg);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.errorCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterErrorCallback(g_avcastcontroller,
        CastControllerErrorCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnPlayerError(errorCode, errorMsg);
    EXPECT_EQ(trigger, true);
}

/**
 * @tc.name: OnEndOfStream001
 * @tc.desc: test OnEndOfStream
 * @tc.type: FUNC
 * @tc.require: none
 */
HWTEST_F(OHAVCastControllerCallbackImplTest, OnEndOfStream001, TestSize.Level0)
{
    int32_t isLooping = 1;
    bool trigger = false;
    OHAVCastControllerCallbackImpl ohAVCastControllerCallbackImpl;

    ohAVCastControllerCallbackImpl.OnEndOfStream(isLooping);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.endOfStreamCallbacks_.empty(), true);

    ohAVCastControllerCallbackImpl.RegisterEndOfStreamCallback(g_avcastcontroller,
        nullptr, &trigger);
    ohAVCastControllerCallbackImpl.OnEndOfStream(isLooping);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.endOfStreamCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterEndOfStreamCallback(g_avcastcontroller,
        CastControllerEndOfStreamCallback, &trigger);
    ohAVCastControllerCallbackImpl.avCastController_ = nullptr;
    ohAVCastControllerCallbackImpl.OnEndOfStream(isLooping);
    EXPECT_EQ(ohAVCastControllerCallbackImpl.endOfStreamCallbacks_.empty(), false);

    ohAVCastControllerCallbackImpl.RegisterEndOfStreamCallback(g_avcastcontroller,
        CastControllerEndOfStreamCallback, &trigger);
    ohAVCastControllerCallbackImpl.OnEndOfStream(isLooping);
    EXPECT_EQ(trigger, true);
}

}  // namespace OHOS::AVSession