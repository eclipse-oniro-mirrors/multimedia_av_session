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

#ifndef OHOS_AVSESSION_CONTROLLER_H
#define OHOS_AVSESSION_CONTROLLER_H

#include <bitset>
#include <memory>
#include <string>
#include <vector>

#include "avcontrol_command.h"
#include "avsession_info.h"
#include "key_event.h"
#include "want_agent.h"

namespace OHOS::AVSession {
class AVSessionController {
public:
    virtual int32_t GetAVPlaybackState(AVPlaybackState& state) = 0;

    virtual int32_t GetAVMetaData(AVMetaData& data) = 0;

    virtual int32_t SendAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    virtual int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability) = 0;

    virtual int32_t GetValidCommands(std::vector<int32_t>& cmds) = 0;

    virtual int32_t IsSessionActive(bool& isActive) = 0;

    virtual int32_t SendControlCommand(const AVControlCommand& cmd) = 0;

    virtual int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) = 0;

    virtual int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) = 0;

    virtual int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) = 0;

    virtual int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) = 0;

    virtual int32_t GetAVQueueTitle(std::string& title) = 0;

    virtual int32_t SkipToQueueItem(int32_t& itemId) = 0;

    virtual int32_t Destroy() = 0;

    virtual std::string GetSessionId() = 0;

    virtual int64_t GetRealPlaybackPosition() = 0;

    virtual bool IsDestroy() = 0;

    virtual ~AVSessionController() = default;
};
} // namespace OHOS::AVSession

#endif // OHOS_AVSESSION_CONTROLLER_H