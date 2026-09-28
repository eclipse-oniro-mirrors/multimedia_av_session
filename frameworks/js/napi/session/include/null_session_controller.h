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

#ifndef OHOS_NULL_SESSION_CONTROLLER_H
#define OHOS_NULL_SESSION_CONTROLLER_H

#include "avsession_controller.h"

namespace OHOS::AVSession {
class NullSessionController : public AVSessionController {
public:
    static std::shared_ptr<NullSessionController> GetInstance()
    {
        static auto instance = std::make_shared<NullSessionController>();
        return instance;
    }

    NullSessionController() = default;
    ~NullSessionController() = default;
    NullSessionController(const NullSessionController&) = delete;
    NullSessionController& operator=(const NullSessionController&) = delete;
    NullSessionController(NullSessionController&&) = delete;
    NullSessionController& operator=(NullSessionController&&) = delete;

    int32_t GetAVCallState(AVCallState& avCallState) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetAVCallMetaData(AVCallMetaData& avCallMetaData) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetAVPlaybackState(AVPlaybackState& state) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetAVMetaData(AVMetaData& data) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SendAVKeyEvent(const MMI::KeyEvent& keyEvent) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability) override
    {
        return ERR_SESSION_NOT_EXIST;
    }
    int32_t GetLaunchAbilityInner(AbilityRuntime::WantAgent::WantAgent*& ability) override
    {
        return ERR_SESSION_NOT_EXIST;
    }
    int32_t GetValidCommands(std::vector<int32_t>& cmds) override { return ERR_SESSION_NOT_EXIST; }
    int32_t IsSessionActive(bool& isActive) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SendControlCommand(const AVControlCommand& cmd) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SendCommonCommand(const std::string& commonCommand,
        const AAFwk::WantParams& commandArgs) override { return ERR_SESSION_NOT_EXIST; }
    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) override
    {
        return AVSESSION_SUCCESS;
    }
    int32_t SetAVCallMetaFilter(const AVCallMetaData::AVCallMetaMaskType& filter) override
    {
        return AVSESSION_SUCCESS;
    }
    int32_t SetAVCallStateFilter(const AVCallState::AVCallStateMaskType& filter) override
    {
        return AVSESSION_SUCCESS;
    }
    int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) override { return AVSESSION_SUCCESS; }
    int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) override
    {
        return AVSESSION_SUCCESS;
    }
    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetAVQueueTitle(std::string& title) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SkipToQueueItem(int32_t& itemId) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetExtras(AAFwk::WantParams& extras) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetExtrasWithEvent(const std::string& extraEvent, AAFwk::WantParams& extras) override
    {
        return ERR_SESSION_NOT_EXIST;
    }
    int32_t GetMediaCenterControlType(std::vector<int32_t>& controlTypes) override
    {
        return ERR_SESSION_NOT_EXIST;
    }
    int32_t GetSupportedPlaySpeeds(std::vector<double>& speeds) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetSupportedLoopModes(std::vector<int32_t>& loopModes) override { return ERR_SESSION_NOT_EXIST; }
    int32_t IsDesktopLyricEnabled(bool& isEnabled) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SetDesktopLyricVisible(bool isVisible) override { return ERR_SESSION_NOT_EXIST; }
    int32_t IsDesktopLyricVisible(bool& isVisible) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SetDesktopLyricState(DesktopLyricState state) override { return ERR_SESSION_NOT_EXIST; }
    int32_t GetDesktopLyricState(DesktopLyricState& state) override { return ERR_SESSION_NOT_EXIST; }
    int32_t SendCustomData(const AAFwk::WantParams& data) override { return ERR_SESSION_NOT_EXIST; }
    int32_t Destroy() override { return AVSESSION_SUCCESS; }
    std::string GetSessionId() override { return ""; }
    int64_t GetRealPlaybackPosition() override { return 0; }
    bool IsDestroy() override { return true; }
};
} // namespace OHOS::AVSession
#endif // OHOS_NULL_SESSION_CONTROLLER_H
