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

/**
 * @brief Session controller instance.
 * @since 9
 */
namespace OHOS::AVSession {
class AVSessionController {
public:
    /**
     * @brief Get current playing status infos.
     *
     * @param state Current playing status infos {@link AVPlaybackState}.
     * @return Returns check whether the system permissions are supported
     * @since 9
    */
    virtual int32_t GetAVPlaybackState(AVPlaybackState& state) = 0;

    /**
     * @brief Get current playing status infos.
     *
     * @param state Current playing status infos {@link AVPlaybackState}.
     * @return Returns check whether the system permissions are supported
     * @since 9
    */
    virtual int32_t GetAVMetaData(AVMetaData& data) = 0;

    /**
     * Send key events to the corresponding session of the controller.
     *
     * @param keyEvent key event.
     * @return int32_t Return whether sending succeeded.
     * @since 9
    */
    virtual int32_t SendAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    /**
     * Get the WantAgent object saved by the application in the session.
     *
     * @param ability Objects saved in setLaunchAbility.
     * @return int32_t Successfully obtained.
     * @since 9
    */
    virtual int32_t GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent& ability) = 0;

    /**
     * Get valid commands supported by the session.
     *
     * @param cmds Returns a collection of valid commands.
     * @return int32_t Whether the valid commands supported by the session are obtained successfully.
     * @since 9
    */
    virtual int32_t GetValidCommands(std::vector<int32_t>& cmds) = 0;

    /**
     * Whether the session is active.
     *
     * @param isActive Whether the session is active.
     * @return int32_t Returns whether the status was obtained successfully.
     * @since 9
    */
    virtual int32_t IsSessionActive(bool& isActive) = 0;

    /**
     * Send commands to its corresponding session through the controller.
     *
     * @param cmd Commands and parameters related to the session {@link AVControlCommand}.
     * @return int32_t Return whether sending succeeded.
     * @since 9
    */
    virtual int32_t SendControlCommand(const AVControlCommand& cmd) = 0;

    /**
     * @brief Listen for AVController Callback event.
     *
     * @param callback Listen for AVController Callback event{@link AVControllerCallback}.
     * @return Returns whether the return is successful.
     * @since 9
    */
    virtual int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) = 0;

    /**
     * @brief Set meta filter.
     *
     * @param filter Meta filter{@link MetaMaskType}.
     * @return Returns whether set successful.
     * @since 9
    */
    virtual int32_t SetMetaFilter(const AVMetaData::MetaMaskType& filter) = 0;

    /**
     * @brief Set Playback filter.
     *
     * @param filter Playback State {@link MetaMaskType}.
     * @return Returns whether set successful.
     * @since 9
    */
    virtual int32_t SetPlaybackFilter(const AVPlaybackState::PlaybackStateMaskType& filter) = 0;

    /**
     * @brief Get the playlist. Which is the content of the playlist presented by this session.
     *
     * @param items An array of the AVQueueItem.
     * @return Return whether the obtain is successful.
     * @since 10
    */
    virtual int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) = 0;

    /**
     * @brief Get the name of the playlist presented by this session.
     *
     * @param title The name of the playlist.
     * @return Return whether the get is successful.
     * @since 10
     */
    virtual int32_t GetAVQueueTitle(std::string& title) = 0;

    /**
     * @brief Set the item in the playlist to be played.
     *
     * @param itemId The serial number of the item to be played.
     * @return Return whether the operation is successful.
     * @since 10
     */
    virtual int32_t SkipToQueueItem(int32_t& itemId) = 0;

    /**
     * @brief Destroy session.
     *
     * @return Returns whether destroy successful.
     * @since 9
    */
    virtual int32_t Destroy() = 0;

    /**
     * @brief Get session id.
     *
     * @return Returns session id.
     * @since 9
    */
    virtual std::string GetSessionId() = 0;

    /**
     * @brief Get current playback position.
     *
     * @return Returns current playback position.
     * @since 9
    */
    virtual int64_t GetRealPlaybackPosition() = 0;

    /**
     * @brief Controller is or not destroy.
     *
     * @return Returns controller is or not destroy.
     * @since 9
    */
    virtual bool IsDestroy() = 0;

    /**
     * @brief Deconstruct AVSessionController.
     * @since 9
    */
    virtual ~AVSessionController() = default;
};
} // namespace OHOS::AVSession

#endif // OHOS_AVSESSION_CONTROLLER_H
