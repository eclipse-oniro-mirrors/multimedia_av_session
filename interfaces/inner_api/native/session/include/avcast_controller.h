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

#ifndef OHOS_AVCAST_CONTROLLER_H
#define OHOS_AVCAST_CONTROLLER_H

#include <bitset>
#include <memory>
#include <string>
#include <vector>

#include "play_info_holder.h"
#include "avsession_info.h"
#include "key_event.h"
#include "i_avcast_controller_proxy.h"
#include "avcast_control_command.h"

/**
 * @brief Session controller instance.
 * @since 9
 */
namespace OHOS::AVSession {
class AVCastController {
public:
    // virtual void Init(const std::shared_ptr<IAVCastControllerProxy> castControllerProxy) = 0;
    /**
     * @brief Get current playing status infos.
     *
     * @param state Current playing status infos {@link AVPlaybackState}.
     * @return Returns check whether the system permissions are supported
     * @since 9
    */
    virtual int32_t Start(const PlayInfoHolder& playInfoHolder) = 0;

    virtual int32_t UpdateMediaInfo(const MediaInfo& mediaInfo) = 0;

    /**
     * Send commands to its corresponding session through the controller.
     *
     * @param cmd Commands and parameters related to the session {@link AVControlCommand}.
     * @return int32_t Return whether sending succeeded.
     * @since 9
    */
    virtual int32_t SendControlCommand(const AVCastControlCommand& cmd) = 0;

    
    /**
     * @brief Listen for AVController Callback event.
     *
     * @param callback Listen for AVController Callback event{@link AVControllerCallback}.
     * @return Returns whether the return is successful.
     * @since 9
    */
    virtual int32_t RegisterCallback(const std::shared_ptr<AVCastControllerCallback>& callback) = 0;

    virtual int32_t GetDuration() = 0;

    virtual std::string GetSurfaceId() = 0;

    virtual int32_t GetVolume() = 0;

    virtual int32_t GetLoopMode() = 0;

    virtual double GetPlaySpeed() = 0;

    virtual int32_t GetCurrentTime() = 0;

    virtual int32_t Destroy() = 0;

    /**
     * @brief Deconstruct AVSessionController.
     * @since 9
    */
    virtual ~AVCastController() = default;
};
} // namespace OHOS::AVSession

#endif // OHOS_AVCAST_CONTROLLER_H
