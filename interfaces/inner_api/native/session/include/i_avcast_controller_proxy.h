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

    IAVCastControllerProxy () = default;
    virtual ~IAVCastControllerProxy () = default;

    virtual void Release() = 0;

    virtual int32_t RegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener> iAVCastControllerProxyListener) = 0;

    virtual int32_t UnregisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener> iAVCastControllerProxyListener) = 0;

    virtual int32_t SetMediaList(const MediaInfoHolder& mediaInfoHolder) = 0;

    virtual void UpdateMediaInfo(const MediaInfo& mediaInfo) = 0;

    virtual void SendControlCommand(const AVCastControlCommand cmd) = 0;

    virtual int32_t GetDuration(int32_t& duration) = 0;

    virtual int32_t GetPosition(int32_t& position) = 0;

    virtual int32_t GetVolume(int32_t& volume) = 0;

    virtual int32_t GetLoopMode(int32_t& loopMode) = 0;

    virtual int32_t GetPlaySpeed(int32_t& playSpeed) = 0;

    virtual int32_t GetPlayState(AVCastPlayerState& playerState) = 0;

    virtual int32_t SetDisplaySurface(std::string& surfaceId) = 0;



};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_CONTROLLER_PROXY_H
