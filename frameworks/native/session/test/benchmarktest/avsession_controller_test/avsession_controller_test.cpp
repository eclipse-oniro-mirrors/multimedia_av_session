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

#include "avmeta_data.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "key_event.h"
#include "want_agent.h"
#include <benchmark/benchmark.h>
#include <string>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace OHOS::AVSession;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace {
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

class AVSessionControllerTest : public benchmark::Fixture {
public:
    AVSessionControllerTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }

    ~AVSessionControllerTest() override = default;

    void SetUp(const ::benchmark::State& state) override
    {
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(g_testBundleName);
        elementName.SetAbilityName(g_testAbilityName);
        avsession_ =
            AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);

        if (avsession_ == nullptr) {
            SLOGE("%{public}s error, failed to CreateSession, avsession_ nullptr.", __func__);
        }

        AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller_);
        if (controller_ == nullptr) {
            SLOGE("%{public}s error, failed to CreateController, controller_ nullptr.", __func__);
        }
    }

    void TearDown(const ::benchmark::State& state) override
    {
        if (avsession_) {
            avsession_->Destroy();
            avsession_ = nullptr;
        }
        if (controller_) {
            controller_->Destroy();
            controller_ = nullptr;
        }
    }

protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;

    std::shared_ptr<AVSession> avsession_;
    std::shared_ptr<AVSessionController> controller_;
};

class AVControllerCallbackImpl : public AVControllerCallback {
public:
    void OnSessionDestroy() override;

    void OnPlaybackStateChange(const AVPlaybackState& state) override;

    void OnMetaDataChange(const AVMetaData& data) override;

    void OnActiveStateChange(bool isActive) override;

    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;

    void OnOutputDeviceChange(const OutputDeviceInfo &outputDeviceInfo) override {};

    ~AVControllerCallbackImpl() override;

    bool isActive_ = false;
    AVMetaData data_;
    AVPlaybackState state_;
    bool isDestory_ = false;
    std::vector<int32_t> cmds_;
};

AVControllerCallbackImpl::~AVControllerCallbackImpl()
{}

void AVControllerCallbackImpl::OnSessionDestroy()
{
    isDestory_ = true;
}

void AVControllerCallbackImpl::OnPlaybackStateChange(const AVPlaybackState& state)
{
    state_ = state;
}

void AVControllerCallbackImpl::OnMetaDataChange(const AVMetaData& data)
{
    data_ = data;
}

void AVControllerCallbackImpl::OnActiveStateChange(bool isActive)
{
    isActive_ = isActive;
}

void AVControllerCallbackImpl::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    cmds_ = cmds;
}

BENCHMARK_F(AVSessionControllerTest, IsSessionActive)(benchmark::State& state)
{
    bool active = false;
    avsession_->Activate();
    while (state.KeepRunning()) {
        controller_->IsSessionActive(active);
        int32_t errCode = controller_->IsSessionActive(active);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to IsSessionActive, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("IsSessionActive failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetAVPlaybackState)(benchmark::State& state)
{
    AVMetaData metaData;
    constexpr int32_t iDuration = 10;
    metaData.Reset();
    metaData.SetAssetId("001");
    metaData.SetDuration(iDuration);
    AVPlaybackState backState;
    backState.SetState(1);
    backState.SetSpeed(1);
    backState.SetBufferedTime(1);
    backState.SetPosition({1, 0});
    backState.SetLoopMode(1);
    backState.SetFavorite(true);
    avsession_->SetAVPlaybackState(backState);
    while (state.KeepRunning()) {
        AVPlaybackState resultState;
        controller_->GetAVPlaybackState(resultState);
        int32_t errCode = controller_->GetAVPlaybackState(resultState);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetAVPlaybackState, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("GetAVPlaybackState failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetAVMetaData)(benchmark::State& state)
{
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("001");
    metaData.SetTitle("123456");
    int32_t errCode = avsession_->SetAVMetaData(metaData);
    if (errCode != AVSESSION_SUCCESS) {
        SLOGE("%{public}s error, failed to SetAVMetaData, error code is %{public}d.", __func__, errCode);
        state.SkipWithError("SetAVMetaData failed, return error.");
    }

    while (state.KeepRunning()) {
        AVMetaData resultMetaData;
        resultMetaData.Reset();
        errCode = controller_->GetAVMetaData(resultMetaData);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetAVMetaData, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("GetAVMetaData failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, SendAVKeyEvent)(benchmark::State& state)
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    item.SetDownTime(1);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    bool isActive = false;

    while (state.KeepRunning()) {
        controller_->IsSessionActive(isActive);
        if (!isActive) {
            avsession_->Activate();
        }
        int32_t errCode = controller_->SendAVKeyEvent(*(keyEvent.get()));
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SendAVKeyEvent, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("SendAVKeyEvent failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetLaunchAbility)(benchmark::State& state)
{
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    int32_t errCode = avsession_->SetLaunchAbility(ability);
    if (errCode != AVSESSION_SUCCESS) {
        SLOGE("%{public}s error, failed to SetLaunchAbility, error code is %{public}d.", __func__, errCode);
        state.SkipWithError("SetLaunchAbility failed, return error.");
    }
    while (state.KeepRunning()) {
        errCode = controller_->GetLaunchAbility(ability);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetLaunchAbility, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("GetLaunchAbility failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetValidCommands)(benchmark::State& state)
{
    std::vector<int32_t> cmds;
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_STOP);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_FAST_FORWARD);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_REWIND);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_SEEK);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_SPEED);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);

    while (state.KeepRunning()) {
        int32_t errCode = controller_->GetValidCommands(cmds);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetValidCommands, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("GetValidCommands failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, SendControlCommand)(benchmark::State& state)
{
    AVControlCommand command;
    avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    command.SetCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    command.SetLoopMode(AVPlaybackState::LOOP_MODE_SEQUENCE);
    while (state.KeepRunning()) {
        bool isActive = false;
        controller_->IsSessionActive(isActive);
        if (!isActive) {
            avsession_->Activate();
        }
        int32_t errCode = controller_->SendControlCommand(command);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SendControlCommand, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("SendControlCommand failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, SetPlaybackFilter)(benchmark::State& state)
{
    while (state.KeepRunning()) {
        AVPlaybackState::PlaybackStateMaskType filter;
        filter.set();
        int32_t errCode = controller_->SetPlaybackFilter(filter);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SetPlaybackFilter, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("SetPlaybackFilter failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetSessionId)(benchmark::State& state)
{
    constexpr int SESSION_LEN = 64;
    while (state.KeepRunning()) {
        std::string sessionId = controller_->GetSessionId();
        if (sessionId.empty() || sessionId.length() != SESSION_LEN) {
            SLOGE("%{public}s error, failed to GetSessionId TestCase.", __func__);
            state.SkipWithError("GetSessionId failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, GetRealPlaybackPosition)(benchmark::State& state)
{
    AVMetaData metaData;
    constexpr int64_t TestMicroSecond = 1000;
    metaData.Reset();
    metaData.SetAssetId("GetRealPlaybackPosition");
    metaData.SetDuration(TestMicroSecond * TestMicroSecond + TestMicroSecond);
    avsession_->SetAVMetaData(metaData);

    AVPlaybackState backState;
    backState.SetPosition({TestMicroSecond * TestMicroSecond, TestMicroSecond});
    avsession_->SetAVPlaybackState(backState);
    AVPlaybackState resultState;
    controller_->GetAVPlaybackState(resultState);
    while (state.KeepRunning()) {
        if (controller_->GetRealPlaybackPosition() <= 0) {
            SLOGE("%{public}s error, failed to GetRealPlaybackPosition.", __func__);
            state.SkipWithError("GetRealPlaybackPosition failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, RegisterCallback)(benchmark::State& state)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    while (state.KeepRunning()) {
        int32_t errCode = controller_->RegisterCallback(callback);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to RegisterCallback, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("RegisterCallback failed, return error.");
        }
    }
}

BENCHMARK_F(AVSessionControllerTest, SetMetaFilter)(benchmark::State& state)
{
    AVMetaData::MetaMaskType filter;
    filter.set(AVMetaData::META_KEY_TITLE);
    while (state.KeepRunning()) {
        int32_t errCode = controller_->SetMetaFilter(filter);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SetMetaFilter, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("SetMetaFilter failed, return error.");
        }
    }
}
} // namespace

// Run the benchmark
BENCHMARK_MAIN();