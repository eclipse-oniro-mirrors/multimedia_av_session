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
    IAVCastControllerProxy() = default;

    /**
     * @brief Deconstruct IAVCastControllerProxy object.
     *
     * @since 10
    */
    virtual ~IAVCastControllerProxy() = default;

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
     * @param { std::shared_ptr<IAVCastControllerProxyListener> }
           iAVCastControllerProxyListener - Unregistered listener.
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
     * @brief Set current queue item.
     *
     * @return { int32_t } refresh queue item result.
     * @since 18
    */
    virtual int32_t RefreshCurrentAVQueueItem(const AVQueueItem& avQueueItem) = 0;

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
     * @brief Send custom data to remote.
     *
     * @param { const std::string } customData - String sended to remote device.
     * @since 10
    */
    virtual void SendCustomData(const std::string &customData) = 0;

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
     * @brief Obtain the decoderTypes of the current media.
     *
     * @param { std::vector<std::string>& } decoderTypes - decoder Type list of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 18
    */
    virtual int32_t GetSupportedDecoders(std::vector<std::string>& decoderTypes) = 0;

    /**
     * @brief Recommended ResolutionLevel of the current media.
     *
     * @param { std::string& } decoderType - decoderType of media.
     * * @param { ResolutionLevel } resolutionLevel - resolutionLevel of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 18
    */
    virtual int32_t GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel) = 0;

    /**
     * @brief Obtain the hdrFormats of the current media.
     *
     * @param { std::vector<HDRFormat>& } hdrFormats - hdrFormats of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 18
    */
    virtual int32_t GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats) = 0;

    /**
     * @brief Obtain the playSpeeds of the current media.
     *
     * @param { std::vector<float>& } playSpeeds - playSpeeds of media.
     * @return { int32_t } Whether the operation was successful.
     * @since 18
    */
    virtual int32_t GetSupportedPlaySpeeds(std::vector<float>& playSpeeds) = 0;

    /**
     * @brief Set valid ability list for current cast session.
     *
     * @param { std::vector<int32_t> } validAbilityList - valid ability list for set.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t SetValidAbility(const std::vector<int32_t>& validAbilityList) = 0;

    /**
     * @brief Get valid ability list for current cast session.
     *
     * @param { std::vector<int32_t> } validAbilityList - valid ability list for get.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t GetValidAbility(std::vector<int32_t> &validAbilityList) = 0;

    /**
     * @brief Set display surface of the current media.
     *
     * @param { std::string& } surfaceId - Surface required for displaying images.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t SetDisplaySurface(std::string& surfaceId) = 0;

    /**
     * @brief Provide key response for drm request.
     *
     * @param { std::string& } assetId - AssetId required for drm response.
     * @param { std::vector<uint8_t> } response - Response required for drm request.
     * @return { int32_t } Whether the operation was successful.
     * @since 10
    */
    virtual int32_t ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response) = 0;

    /**
     * @brief Set Cast Capsule callback for session item.
     *
     * @param { std::function<void(bool, bool)>& } callback - callback for session item.
     * 
     * @since 20
    */
    virtual void SetSessionCallbackForCastCap(const std::function<void(bool, bool)>& callback) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_CONTROLLER_PROXY_H
