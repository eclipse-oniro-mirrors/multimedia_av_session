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

#ifndef OHOS_AVSESSION_H
#define OHOS_AVSESSION_H

#include <string>
#include <memory>

#include "avsession_info.h"
#include "want_agent.h"
#include "want_params.h"
#include "avsession_controller.h"
/**
 * @brief Session, which can be used to set metadata, play status information and other operations.
 * @since 9
 */
namespace OHOS::AVSession {
class AVSession {
public:
    enum {
        SESSION_TYPE_INVALID = -1,
        SESSION_TYPE_AUDIO = 0,
        SESSION_TYPE_VIDEO = 1
    };

    /**
     * @brief Get current session id.
     *
     * @return Returns current session id.
     * @since 9
    */
    virtual std::string GetSessionId() = 0;

    /**
     * Get the metadata of the current session.
     * @param AVMetadata Session metadata {@link AVMetadata}.
     * @since 9
    */
    virtual int32_t GetAVMetaData(AVMetaData& meta) = 0;

    /**
     * Set session metadata.
     * @param AVMetadata Session metadata {@link AVMetadata}.
     * @since 9
    */
    virtual int32_t SetAVMetaData(const AVMetaData& meta) = 0;

    /**
     * @brief Get current playing status infos.
     *
     * @param state Current playing status infos {@link AVPlaybackState}.
     * @return Returns check whether the system permissions are supported.
     * @since 9
    */
    virtual int32_t GetAVPlaybackState(AVPlaybackState& state) = 0;

    /**
     * @brief Set session playback status information.
     *
     * @param state Current playing status infos {@link AVPlaybackState}.
     * @return Return whether the setting is successful.
     * @since 9
    */
    virtual int32_t SetAVPlaybackState(const AVPlaybackState& state) = 0;

    /**
     * @brief Get the playlist. Which is the content of the playlist presented by this session.
     *
     * @param items An array of the AVQueueItem.
     * @return Return whether the obtain is successful.
     * @since 10
    */
    virtual int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) = 0;

    /**
     * @brief Set the playlist. Identifies the content of the playlist presented by this session.
     *
     * @param items An array of the AVQueueItem.
     * @return Return whether the setting is successful.
     * @since 10
    */
    virtual int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) = 0;
  
    /**
     * @brief Get the name of the playlist presented by this session.

     * @param title The name of the playlist.
     * @return Return whether the get is successful.
     * @since 10
     */
    virtual int32_t GetAVQueueTitle(std::string& title) = 0;
  
    /**
     * @brief Set the name of the playlist presented by this session.

     * @param title The name of the playlist.
     * @return Return whether the set is successful.
     * @since 10
     */
    virtual int32_t SetAVQueueTitle(const std::string& title) = 0;

    /**
     * @brief Set a WantAgent's ability to pull up the session.
     *
     * @param ability Relevant attribute information of the application{@link WantAgent}.
     * @return Return whether the setting is successful.
     * @since 9
    */
    virtual int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) = 0;

    /**
     * @brief Get custom media packet.
     *
     * @param extras Custom media packet key-value pairs passed
     * @return Return whether the getting is successful
     * @since 10
    */
    virtual int32_t GetExtras(AAFwk::WantParams& extras) = 0;

    /**
     * @brief Set custom media packet.
     *
     * @param extras Custom media packet key-value pairs passed
     * @return Return whether the setting is successful
     * @since 10
    */
    virtual int32_t SetExtras(const AAFwk::WantParams& extras) = 0;

    /**
     * @brief Get the controller corresponding to this session.
     *
     * @return Return to session controller{@link AVSessionController}.
     * @since 9
    */
    virtual std::shared_ptr<AVSessionController> GetController() = 0;

    /**
     * @brief Listen for AVSession Callback event.
     *
     * @param callback Listen for AVSession Callback event{@link AVSessionCallback}.
     * @return Returns whether the return is successful.
     * @since 9
    */
    virtual int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) = 0;

    /**
     * @brief Activate session.
     *
     * @return Return whether the setting is successful
     * @since 9
    */
    virtual int32_t Activate() = 0;

    /**
     * @brief Disable the function of the current session.
     *
     * @return Return whether the setting is successful
     * @since 9
    */
    virtual int32_t Deactivate() = 0;

    /**
     * @brief Get whether the session is activated.
     *
     * @return Return whether the setting is successful
     * @since 9
    */
    virtual bool IsActive() = 0;

    /**
     * @brief Destroy session.
     *
     * @return Return whether the setting is successful
     * @since 9
    */
    virtual int32_t Destroy() = 0;

    /**
     * @brief Add Support Command.
     *
     * @param cmd Commands to be added.
     * @return Return whether the addition was successful.
     * @since 9
    */
    virtual int32_t AddSupportCommand(const int32_t cmd) = 0;

    /**
     * @brief Delete Support Command.
     *
     * @param cmd Commands to be deleted.
     * @return Return whether the deletion was successful.
     * @since 9
    */
    virtual int32_t DeleteSupportCommand(const int32_t cmd) = 0;

    /**
     * @brief Set session events.
     *
     * @param event Name of the session event set
     * @param args Session event key-value pairs passed
     * @return Return whether the setting is successful
     * @since 9
    */
    virtual int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) = 0;

    /**
     * @brief Deconstruct AVSession object.
     *
     * @since 9
    */
    virtual ~AVSession() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_H
