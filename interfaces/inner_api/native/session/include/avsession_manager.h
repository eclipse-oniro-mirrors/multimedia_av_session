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
     * Send the key command to get the descriptor of all sessions.
     *
     * @param descriptors Get relevant descriptions of all sessions
     * @return Whether the relevant descriptions of all sessions are obtained successfully
     * @since 9
    */
    virtual int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors) = 0;

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
     * Create a session controller based on the session ID.
     *
     * @param sessionId Current session id.
     * @param controller Session controller{@link AVSessionController}
     * @return Whether the session controller was successfully created
     * @since 9
    */
    virtual int32_t CreateController(const std::string& sessionId,
        std::shared_ptr<AVSessionController>& controller) = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    virtual int32_t GetAVCastController(const std::string& sessionId,
        std::shared_ptr<AVCastController>& castController) = 0;
#endif

    /**
     * @brief Listen for sessionListener callback event.
     *
     * @param listener Listen for sessionListener Callback event{@link SessionListener}.
     * @return Whether to return successful Listener.
     * @since 9
    */
    virtual int32_t RegisterSessionListener(const std::shared_ptr<SessionListener>& listener) = 0;

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
     * Send system key command.
     *
     * @param keyEvent Key event {@linkKeyEvent}
     * @return Returns whether the key event was successfully sent to the top session.
     * @since 9
    */
    virtual int32_t SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent) = 0;

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

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    /**
     * Discovery nearby devices that can be cast.
     *
     * @param castDeviceCapability Device capability to filter device list
     * @return Returns whether the device was successfully found
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability) = 0;

    /**
     * Stop cast process.
     *
     * @return Returns
     * @since 10
    */
    virtual int32_t StopCastDiscovery() = 0;

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
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_MANAGER_H
