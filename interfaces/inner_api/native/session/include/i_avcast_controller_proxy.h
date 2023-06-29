/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_I_AVCAST_CONTROLLER_PROXY_H
#define OHOS_I_AVCAST_CONTROLLER_PROXY_H

#include <string>
#include "avplayback_state.h"
#include "media_info_holder.h"
#include "media_info.h"
#include "avcast_control_command.h"
#include "avsession_info.h"

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class IAVCastControllerProxy {
public:
    /**
     * @brief Construct IAVCastControllerProxy object.
     *
     * @since 10
    */
    IAVCastControllerProxy () = default;

    /**
     * @brief Deconstruct IAVCastControllerProxy object.
     *
     * @since 10
    */
    virtual ~IAVCastControllerProxy () = default;

    /**
     * @brief Release IAVCastControllerProxy object.
     *
     * @since 10
    */
    virtual void Release() = 0;

    /**
     * @brief Register listener for AVCast controller callback event.
     *
     * @param { std::shared_ptr<IAVCastControllerProxyListener> } iAVCastControllerProxyListener - Register listener.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t RegisterControllerListener(
        const std::shared_ptr<IAVCastControllerProxyListener> iAVCastControllerProxyListener) = 0;

    /**
     * @brief Unregister listener for AVCast state callback event.
     *
     * @param { std::shared_ptr<IAVCastSessionStateListener> } iAVCastControllerProxyListener - Unregistered listener.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t UnRegisterControllerListener(
        const std::shared_ptr<IAVCastControllerProxyListener> iAVCastControllerProxyListener) = 0;

    /**
     * @brief Get current queue item.
     *
     * @return { AVQueueItem } current queue item.
     * @since 10
    */
    virtual AVQueueItem GetCurrentItem() = 0;

    /**
     * @brief Set media info (avQueueItem) to remote, and play immediately.
     *
     * @param { const AVQueueItem& } avQueueItem - AVQueueItem that need to be played.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t Start(const AVQueueItem& avQueueItem) = 0;

    /**
     * @brief Set media info (avQueueItem) to remote, but won't play immediately.
     *
     * @param { const AVQueueItem& } avQueueItem - AVQueueItem that need to be played.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t Prepare(const AVQueueItem& avQueueItem) = 0;

    /**
     * @brief Send control command to remote.
     *
     * @param { const AVCastControlCommand } cmd - Command to be executed at remote device.
     * @since 10
    */
    virtual void SendControlCommand(const AVCastControlCommand cmd) = 0;

    /**
     * @brief Obtain the duration of the current media.
     *
     * @param { int32_t& } duration - Duration of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t GetDuration(int32_t& duration) = 0;

    /**
     * @brief Obtain the AVPlaybackState of the current media.
     *
     * @param { AVPlaybackState& } avPlaybackState - AVPlaybackState of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) = 0;

    /**
     * @brief Set display surface of the current media.
     *
     * @param { std::string& } surfaceId - Surface required for displaying images.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t SetDisplaySurface(std::string& surfaceId) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_CONTROLLER_PROXY_H
