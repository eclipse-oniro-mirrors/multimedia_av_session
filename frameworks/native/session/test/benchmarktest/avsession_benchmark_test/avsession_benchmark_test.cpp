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

#include <benchmark/benchmark.h>
#include <unistd.h>

#include "avcontrol_command.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "want_agent.h"
#include "want_params.h"

using namespace OHOS::AVSession;

namespace {
static int32_t g_onCall = AVSESSION_ERROR;
static int32_t g_sessionId = AVSESSION_ERROR;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

class AVSessionTest : public benchmark::Fixture {
public:
    AVSessionTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }

    ~AVSessionTest() override = default;
    void SetUp(const ::benchmark::State& state) override
    {
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(g_testBundleName);
        elementName.SetAbilityName(g_testAbilityName);
        avsession_ =
            AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
        if (avsession_ == nullptr) {
            SLOGE("%{public}s error, failed to CreateSession, avsession_ nullptr.", __func__);
            return;
        }
        g_sessionId++;
        AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller_);
        if (controller_ == nullptr) {
            SLOGE("%{public}s error, failed to CreateController, controller_ nullptr.", __func__);
        }
    }

    void TearDown(const ::benchmark::State& state) override
    {
        int32_t ret = AVSESSION_ERROR;
        if (avsession_) {
            ret = avsession_->Destroy();
            avsession_ = nullptr;
        }
        if (controller_) {
            ret = controller_->Destroy();
            controller_ = nullptr;
        }
        g_onCall = AVSESSION_ERROR;
    }

protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;
    static constexpr int SESSION_LEN = 64;
    std::shared_ptr<AVSession> avsession_;
    std::shared_ptr<AVSessionController> controller_;
};

class AVSessionCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo) override {};
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override {};

    ~AVSessionCallbackImpl() override;
};

void AVSessionCallbackImpl::OnPlay()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnPlay %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnPause()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnPause %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnStop()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnStop %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnPlayNext()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnPlayNext %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnPlayPrevious()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnPlayPrevious %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnFastForward()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnFastForward %{public}d", g_onCall);
}
void AVSessionCallbackImpl::OnRewind()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnRewind %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnSeek(int64_t time)
{
    SLOGI("OnSeek %{public}" PRId64, time);
    g_onCall = AVSESSION_SUCCESS;
}

void AVSessionCallbackImpl::OnSetSpeed(double speed)
{
    SLOGI("OnSetSpeed %{public}f", speed);
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnSetSpeed %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnSetLoopMode(int32_t loopMode)
{
    SLOGI("OnSetLoopMode %{public}d", loopMode);
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnSetLoopMode %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnToggleFavorite(const std::string& mediald)
{
    SLOGI("OnToggleFavorite %{public}s", mediald.c_str());
    g_onCall = AVSESSION_SUCCESS;
    SLOGI("OnToggleFavorite %{public}d", g_onCall);
}

void AVSessionCallbackImpl::OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    SLOGI("OnMediaKeyEvent");
    g_onCall = AVSESSION_SUCCESS;
}

void AVSessionCallbackImpl::OnCommonCommand(const std::string& commonCommand,
    const OHOS::AAFwk::WantParams& commandArgs)
{
    SLOGI("OnCommonCommand");
    g_onCall = AVSESSION_SUCCESS;
}

AVSessionCallbackImpl::~AVSessionCallbackImpl()
{
}

BENCHMARK_F(AVSessionTest, GetSessionIdTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        auto sessionId = avsession_->GetSessionId();
        if (sessionId.empty() || sessionId.length() != SESSION_LEN) {
            state.SkipWithError("GetSessionIdTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, SetAVMetaDataTestCase)(benchmark::State& state)
{
    const int32_t iDuration = 40000;
    AVMetaData metaData;
    while (state.KeepRunning()) {
        metaData.Reset();
        metaData.SetAssetId("123");
        metaData.SetTitle("Black Humor");
        metaData.SetArtist("zhoujielun");
        metaData.SetAuthor("zhoujielun");
        metaData.SetAlbum("Jay");
        metaData.SetWriter("zhoujielun");
        metaData.SetComposer("zhoujielun");
        metaData.SetDuration(iDuration);
        metaData.SetMediaImageUri("https://baidu.yinyue.com");
        metaData.SetSubTitle("fac");
        metaData.SetDescription("for friends");
        metaData.SetLyric("https://baidu.yinyue.com");
        OHOS::ErrCode errCode = avsession_->SetAVMetaData(metaData);
        if (errCode != OHOS::ERR_OK) {
            state.SkipWithError("SetAVMetaDataTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, GetAVMetaDataTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        AVMetaData metaData;
        metaData.Reset();
        OHOS::ErrCode errCode = avsession_->GetAVMetaData(metaData);
        if (errCode != OHOS::ERR_OK) {
            state.SkipWithError("GetAVMetaDataTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, SetAVPlaybackStateTestCase)(benchmark::State& state)
{
    const int32_t iPosition = 80000;
    const int32_t iBufferedTime = 700000;
    while (state.KeepRunning()) {
        AVPlaybackState playbackState;
        playbackState.SetState(1);
        playbackState.SetSpeed(1);
        playbackState.SetPosition({iPosition, 0});
        playbackState.SetBufferedTime(iBufferedTime);
        playbackState.SetLoopMode(1);
        playbackState.SetFavorite(true);
        int32_t ret = avsession_->SetAVPlaybackState(playbackState);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SetAVPlaybackStateTestCase", __func__);
            state.SkipWithError("SetAVPlaybackStateTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, GetAVPlaybackStateTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        AVPlaybackState backState;
        int32_t ret = avsession_->GetAVPlaybackState(backState);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetAVPlaybackStateTestCase", __func__);
            state.SkipWithError("GetAVPlaybackStateTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, SetLaunchAbilityTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        OHOS::AbilityRuntime::WantAgent::WantAgent ability;
        int32_t ret = avsession_->SetLaunchAbility(ability);

        if (ret != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SetLaunchAbilityTestCase", __func__);
            state.SkipWithError("SetLaunchAbilityTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, GetControllerTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        auto controller = avsession_->GetController();
        if (controller == nullptr) {
            SLOGE("%{public}s error, failed to GetControllerTestCase", __func__);
            state.SkipWithError("GetControllerTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, RegisterCallbackTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCallbackImpl>();
        OHOS::ErrCode errCode = avsession_->RegisterCallback(callback);
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to RegisterCallbackTestCase, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("RegisterCallbackTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, ActivateTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        OHOS::ErrCode errCode = avsession_->Activate();
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to ActivateTestCase, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("ActivateTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, DeactivateTestCase)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        OHOS::ErrCode errCode = avsession_->Deactivate();
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to DeactivateTestCase, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("DeactivateTestCase failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, AddSupportCommand)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
        OHOS::ErrCode errCode = avsession_->AddSupportCommand(cmd);
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to AddSupportCommand, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("AddSupportCommand failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, DeleteSupportCommand)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        int32_t cmd = AVControlCommand::SESSION_CMD_PLAY;
        OHOS::ErrCode errCode = avsession_->DeleteSupportCommand(cmd);
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to DeleteSupportCommand, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("DeleteSupportCommand failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionTest, SetSessionEvent)(benchmark::State& state)
{
    const std::string event = "dynamic_lyrics";
    const OHOS::AAFwk::WantParams args;
    while (state.KeepRunning()) {
        OHOS::ErrCode errCode = avsession_->SetSessionEvent(event, args);
        if (errCode != OHOS::ERR_OK) {
            SLOGE("%{public}s error, failed to SetSessionEvent, error code is %{public}d.", __func__,
                errCode);
            state.SkipWithError("SetSessionEvent failed, return error.");
        }
    }
}
} // namespace

// Run the benchmark
BENCHMARK_MAIN();