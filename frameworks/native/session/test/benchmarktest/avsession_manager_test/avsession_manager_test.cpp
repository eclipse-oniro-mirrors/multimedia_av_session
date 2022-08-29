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
#include <string>
#include <unistd.h>
#include <vector>
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "key_event.h"
#include "want_agent.h"

using namespace std;
using namespace OHOS::AVSession;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace {
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
        descriptor_ = descriptor;
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
        descriptor_ = descriptor;
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    std::string GetSessionId() const
    {
        return descriptor_.sessionId_;
    }

private:
    AVSessionDescriptor descriptor_;
};

class AVSessionManagerTest : public benchmark::Fixture {
public:
    AVSessionManagerTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }

    ~AVSessionManagerTest() override = default;
protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;
};

/**
 * @tc.name: CreatSession
 * @tc.desc: invalid params
 * @tc.type: FUNC
 * @tc.require: AR000H31JC
 */
BENCHMARK_F(AVSessionManagerTest, CreatSession)(benchmark::State& state)
{
    SLOGI("BenchMark CreatSession test begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    while (state.KeepRunning()) {
        auto session =
            AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
        if (session != nullptr) {
            session->Destroy();
        } else {
            SLOGE("%{public}s error, failed to CreatSession!", __func__);
            state.SkipWithError("CreatSession failed, return error.");
        }
    }

    SLOGI("BenchMark CreatSession test end");
}

/**
 * @tc.name: GetAllSessionDescriptors
 * @tc.desc: Get all session descriptors
 * @tc.type: FUNC
 * @tc.require: AR000H31JC
 */
BENCHMARK_F(AVSessionManagerTest, GetAllSessionDescriptors)(benchmark::State& state)
{
    SLOGI("BenchMark GetAllSessionDescriptors test begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    auto session = AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                                                                 elementName);
    while (state.KeepRunning()) {
        std::vector<AVSessionDescriptor> descriptors;
        auto errCode = AVSessionManager::GetInstance().GetAllSessionDescriptors(descriptors);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetAllSessionDescriptors, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("GetAllSessionDescriptors failed, return error.");
        }
    }
    if (session != nullptr) {
        session->Destroy();
    }
    SLOGI("BenchMark GetAllSessionDescriptors test end");
}

/**
 * @tc.name: GetActivatedSessionDescriptors
 * @tc.desc: Get all activated session descriptors
 * @tc.type: FUNC
 * @tc.require: AR000H31JC
 */
BENCHMARK_F(AVSessionManagerTest, GetActivatedSessionDescriptors)(benchmark::State& state)
{
    SLOGI("BenchMark GetActivatedSessionDescriptors test begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    auto session =
        AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    session->Activate();
    while (state.KeepRunning()) {
        std::vector<AVSessionDescriptor> descriptors;
        auto errCode = AVSessionManager::GetInstance().GetActivatedSessionDescriptors(descriptors);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetActivatedSessionDescriptors, error code is %{public}d.",
                        __func__, errCode);
            state.SkipWithError("GetActivatedSessionDescriptors failed, return error.");
        }
    }
    if (session != nullptr) {
        session->Destroy();
    }
    SLOGI("BenchMark GetActivatedSessionDescriptors test end");
}

/**
 * @tc.name: GetDescriptorsBySessionId
 * @tc.desc: Get session descriptors by sessionId
 * @tc.type: FUNC
 * @tc.require: AR000H31JC
 */
BENCHMARK_F(AVSessionManagerTest, GetDescriptorsBySessionId)(benchmark::State& state)
{
    SLOGI("BenchMark GetDescriptorsBySessionId test begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    auto session = AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO,
                                                                 elementName);
    session->Activate();
    auto sessionId = session->GetSessionId();
    while (state.KeepRunning()) {
        AVSessionDescriptor descriptor{};
        auto errCode = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(sessionId, descriptor);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to GetSessionDescriptorsBySessionId, error code is %{public}d.", __func__,
                  errCode);
            state.SkipWithError("GetSessionDescriptorsBySessionId failed, return error.");
        }
    }
    if (session != nullptr) {
        session->Destroy();
    }
    SLOGI("BenchMark GetDescriptorsBySessionId test end");
}

/**
 * @tc.name: CreateController
 * @tc.desc: create session controller
 * @tc.type: FUNC
 * @tc.require: AR000H31JI
 */
BENCHMARK_F(AVSessionManagerTest, CreateController)(benchmark::State& state)
{
    SLOGI("BenchMark CreateController test begin");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    auto session =
        AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    while (state.KeepRunning()) {
        std::shared_ptr<AVSessionController> controller;
        auto errCode = AVSessionManager::GetInstance().CreateController(session->GetSessionId(), controller);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to CreateController, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("CreateController failed, return error.");
        }
        if (controller != nullptr) {
            controller->Destroy();
        }
    }
    if (session != nullptr) {
        session->Destroy();
    }
    SLOGI("BenchMark CreateController test end");
}

/**
 * @tc.name: RegisterServiceDeathCallback
 * @tc.desc: register service death listener
 * @tc.type: FUNC
 * @tc.require: AR000H31JB
 */
BENCHMARK_F(AVSessionManagerTest, RegisterServiceDeathCallback)(benchmark::State& state)
{
    SLOGI("BenchMark RegisterServiceDeathCallback test begin");
    while (state.KeepRunning()) {
        bool isDead = false;
        auto errCode = AVSessionManager::GetInstance().RegisterServiceDeathCallback([&isDead]() { isDead = true; });
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to RegisterServiceDeathCallback, error code is %{public}d.", __func__,
                  errCode);
            state.SkipWithError("RegisterServiceDeathCallback failed, return error.");
        }
        errCode = AVSessionManager::GetInstance().UnregisterServiceDeathCallback();
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to UnregisterServiceDeathCallback, error code is %{public}d.", __func__,
                  errCode);
            state.SkipWithError("UnregisterServiceDeathCallback failed, return error.");
        }
    }
    SLOGI("BenchMark RegisterServiceDeathCallback test end");
}

/**
 * @tc.name: SendSystemMediaKeyEvent
 * @tc.desc: valid keyEvent
 * @tc.type: FUNC
 * @tc.require: AR000H31JB
 */
BENCHMARK_F(AVSessionManagerTest, SendSystemMediaKeyEvent)(benchmark::State& state)
{
    SLOGI("BenchMark SendSystemMediaKeyEvent test begin");
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(1000);
    auto keyItem = OHOS::MMI::KeyEvent::KeyItem();
    keyItem.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_MEDIA_PLAY);
    keyItem.SetDownTime(1000);
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);
    while (state.KeepRunning()) {
        auto errCode = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*keyEvent);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SendSystemMediaKeyEvent, error code is %{public}d.", __func__, errCode);
            state.SkipWithError("SendSystemMediaKeyEvent failed, return error.");
        }
    }
    SLOGI("BenchMark SendSystemMediaKeyEvent test end");
}

/**
 * @tc.name: SendSystemControlCommand
 * @tc.desc: valid command
 * @tc.type: FUNC
 * @tc.require: AR000H31JB
 */
BENCHMARK_F(AVSessionManagerTest, SendSystemControlCommand)(benchmark::State& state)
{
    SLOGI("BenchMark SendSystemControlCommand test begin");
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
    while (state.KeepRunning()) {
        auto errCode = AVSessionManager::GetInstance().SendSystemControlCommand(command);
        if (errCode != AVSESSION_SUCCESS) {
            SLOGE("%{public}s error, failed to SendSystemControlCommand, error code is %{public}d.", __func__,
                        errCode);
            state.SkipWithError("SendSystemControlCommand failed, return error.");
        }
    }
    SLOGI("BenchMark SendSystemControlCommand test end");
}
} // namespace

// Run the benchmark
BENCHMARK_MAIN();