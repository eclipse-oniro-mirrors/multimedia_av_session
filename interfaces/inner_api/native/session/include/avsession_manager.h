/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_MANAGER_H
#define OHOS_AVSESSION_MANAGER_H

#include <functional>
#include <string>
#include <memory>

#include "audio_system_manager.h"
#include "av_session.h"
#include "avsession_controller.h"
#include "avsession_info.h"
#include "key_event.h"
#include "avqueue_info.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller.h"
#endif

namespace OHOS::AVSession {
class AVSessionManager {
public:
    /**
     * Get AVSessionManager instance.
     *
     * @return AVSessionManager instance.
     * @since 7
    */
    static AVSessionManager& GetInstance();

    /**
     * Create Session Object.
     *
     * @param tag Custom name of the session
     * @param type Session type
     * @param elementName element Name
     * @return Returns Session Object
     * @since 7
    */
    virtual std::shared_ptr<AVSession> CreateSession(const std::string& tag, int32_t type,
                                                     const AppExecFwk::ElementName& elementName) = 0;

    /**
     * Create Session Object.
     *
     * @param tag Custom name of the session
     * @param type Session type
     * @param elementName element Name
     * @param session Created session {@link AVSession}
     * @return Returns result of creating session
     * @since 12
    */
    virtual int32_t CreateSession(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName,
                                  std::shared_ptr<AVSession>& session) = 0;
    /**
     * Send the key command to get the descriptor of all sessions.
     *
     * @param descriptors Get relevant descriptions of all sessions
     * @return Whether the relevant descriptions of all sessions are obtained successfully
     * @since 9
    */
    virtual int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) = 0;

    /**
     * Send the key command to get the descriptor of sessions.
     *
     * @param category Session category for different scenes {@link SessionCategory}.
     * @param descriptors Get relevant descriptions of sessions
     * @return Whether the relevant descriptions of sessions are obtained successfully
     * @since 23
    */
    virtual int32_t GetSessionDescriptors(int32_t category, std::vector<AVSessionDescriptor>& descriptors) = 0;

    /**
     * Send the key command to get the descriptor of activated sessions.
     *
     * @param activatedSessions Get relevant descriptions of activated sessions
     * @return Returns whether the relevant descriptions of activated sessions are obtained successfully
     * @since 9
    */
    virtual int32_t GetActivatedSessionDescriptors(std::vector<AVSessionDescriptor>& activatedSessions) = 0;

    /**
     * Get SessionDescriptors By SessionId.
     *
     * @param sessionId current session id.
     * @param descriptor obtain SessionDescriptors {@link AVSessionDescriptor}.
     * @return Returns whether to obtain SessionDescriptors successfully.
     * @since 9
    */
    virtual int32_t GetSessionDescriptorsBySessionId(const std::string& sessionId, AVSessionDescriptor& descriptor) = 0;

    /**
     * Get historical session Descriptors.
     *
     * @param maxSize data write maxSize.
     * @param descriptors obtain SessionDescriptors {@link AVSessionDescriptor}.
     * @return Returns whether to obtain SessionDescriptors successfully.
     * @since 9
    */
    virtual int32_t GetHistoricalSessionDescriptors(int32_t maxSize, std::vector<AVSessionDescriptor>& descriptors) = 0;
    
    /**
     * Get historical AVQueueInfo.
     *
     * @param maxSize data write maxSize.
     * @param maxAppSize max app count.
     * @param avQueueInfo obtain history play avqueue {@link AVQueueInfo}.
     * @return Returns whether to obtain AVQueueInfo successfully.
     * @since 11
    */
    virtual int32_t GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
        std::vector<AVQueueInfo>& avQueueInfo) = 0;

    /**
     * Create a session controller based on the session ID.
     *
     * @param sessionId Current session id.
     * @param controller Session controller{@link AVSessionController}
     * @return Whether the session controller was successfully created
     * @since 9
    */
    virtual int32_t CreateController(const std::string& sessionId,
        std::shared_ptr<AVSessionController>& controller) = 0;

    /**
     * @brief Listen for sessionListener callback event for current user.
     *
     * @param listener Listen for sessionListener Callback event{@link SessionListener}.
     * @return Whether to return successful Listener.
     * @since 9
    */
    virtual int32_t RegisterSessionListener(const std::shared_ptr<SessionListener>& listener) = 0;

    /**
     * @brief Listen for sessionListener callback event for all users.
     *
     * @param listener Listen for sessionListener Callback event{@link SessionListener}.
     * @return Whether to return successful Listener.
     * @since 9
    */
    virtual int32_t RegisterSessionListenerForAllUsers(const std::shared_ptr<SessionListener>& listener) = 0;

    /**
     * @brief Listen for service death callback event.
     *
     * @param callback Listen for death callback event{@link DeathCallback}.
     * @return Whether to return successful callback.
     * @since 9
    */
    virtual int32_t RegisterServiceDeathCallback(const DeathCallback& callback) = 0;

    /**
     * @brief Listen for service death callback event.
     *
     * @param callback Listen for death callback event{@link DeathCallback}.
     * @return Whether to return successful callback.
     * @since 9
    */
    virtual int32_t UnregisterServiceDeathCallback() = 0;

    /**
     * @brief Listen for service start callback event.
     *
     * @param callback Listen for service start event.
     * @return Whether to return successful callback.
     * @since 9
    */
    virtual int32_t RegisterServiceStartCallback(const std::function<void()> serviceStartCallback) = 0;

    /**
     * @brief Listen for service startcallback event.
     *
     * @return Whether to return successful callback.
     * @since 9
    */
    virtual int32_t UnregisterServiceStartCallback() = 0;

    /**
     * Send system key command.
     *
     * @param keyEvent Key event {@linkKeyEvent}
     * @return Returns whether the key event was successfully sent to the top session.
     * @since 9
    */
    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

    /**
     * Send system key command.
     *
     * @param keyEvent Key event {@linkKeyEvent}
     * @param wantParam The wantParam
     * @return Returns whether the key event was successfully sent to the top session.
     * @since 18
    */
    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent, const AAFwk::Want &wantParam) = 0;

    /**
     * Send system control command.
     *
     * @param command Relevant commands and parameters of AVSession {@AVControlCommand}
     * @return Returns whether send control command to the top session.
     * @since 9
    */
    virtual int32_t SendSystemControlCommand(const AVControlCommand& command) = 0;

    /**
     * Cast the session to the specified device list.
     *
     * @param token Session token
     * @param descriptors Media device list {@link AudioDeviceDescriptor}
     * @return Returns whether the session was successfully cast to the specified device list
     * @since 9
    */
    virtual int32_t CastAudio(const SessionToken& token,
                              const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;

    /**
     * Cast all sessions to the specified device list.
     *
     * @param descriptors Media device list {@link AudioDeviceDescriptor}
     * @return Returns whether the session was successfully cast to the specified device list
     * @since 9
    */
    virtual int32_t CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors) = 0;
    
    /**
     * Start media playback
     *
     * @param bundleName bundleName.
     * @param assetId assetId of media for playback.
     * @return Returns whether to Start media playback successfully.
     * @since 11
    */
    virtual int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId,
        const std::string& moduleName = "") = 0;

    /**
     * @brief Listen for AncoMediaSessionListener callback event.
     *
     * @param listener Listen for AncoMediaSessionListener Callback event{@link AncoMediaSessionListener}.
     * @return Whether to return successful Listener.
     * @since 20
    */
    virtual int32_t RegisterAncoMediaSessionListener(const std::shared_ptr<AncoMediaSessionListener> &listener) = 0;

    /**
     * Close avsession manager, clear resources.
     *
     * @return Returns whether close the avsession manager.
     */
    virtual int32_t Close(void) = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    virtual int32_t GetAVCastController(const std::string& sessionId,
        std::shared_ptr<AVCastController>& castController) = 0;

    /**
     * Discovery nearby devices that can be cast.
     *
     * @param castDeviceCapability Device capability to filter device list
     * @return Returns whether the device was successfully found
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability, std::vector<std::string> drmSchemes) = 0;

    /**
     * Stop cast process.
     *
     * @return Returns
     * @since 10
    */
    virtual int32_t StopCastDiscovery() = 0;

    /**
     * Transmission fd
     *
     * @param fd file descriptor
     * @param maxSize file max size
     * @return Returns whether the fd was transport successfully
     * @since 13
    */
    virtual int32_t StartDeviceLogging(int32_t fd, uint32_t maxSize) = 0;

    /**
     * Stop transmission fd
     *
     * @return Returns whether stop transport successfully
     * @since 13
    */
    virtual int32_t StopDeviceLogging() = 0;

    /**
     * Start cast process.
     *
     * @param sessionToken Session token
     * @param outputDeviceInfo outputdeviceInfo
     * @return Returns whether the device was successfully found
     * @since 10
    */
    virtual int32_t StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo) = 0;
    
    /**
     * Start cast process.
     *
     * @param sessionToken Session token
     * @param outputDeviceInfo outputdeviceInfo
     * @return Returns whether the device was successfully found
     * @since 10
    */
    virtual int32_t StopCast(const SessionToken& sessionToken) = 0;

    virtual int32_t SetDiscoverable(const bool enable) = 0;
#endif

    /**
     * Get distributed session controllers.
     *
     * @param sessionType sessionType
     * @param sessionControllers sessionControllers
     * @return Returns whether get distributed session controller successfully.
     * @since 16
    */
    virtual int32_t GetDistributedSessionControllers(const DistributedSessionType& sessionType,
        std::vector<std::shared_ptr<AVSessionController>>& sessionControllers) = 0;

    /**
     * Get session already alive.
     *
     * @param elementName element Name
     * @param tag Custom name of the session
     * @param session wanted session {@link AVSession}
     * @return Returns result of getting session
     * @since 21
    */
    virtual int32_t GetSession(const AppExecFwk::ElementName& elementName,
        std::string& tag, std::shared_ptr<AVSession>& session) = 0;

    /**
     * Check whether the desktop lyric feature is supported.
     *
     * @param isSupported Whether the desktop lyric feature is supported
     * @return Return whether the request for enabling the desktop lyrics feature was successful.
     * @since 23
    */
    virtual int32_t IsDesktopLyricSupported(bool &isSupported) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_H
