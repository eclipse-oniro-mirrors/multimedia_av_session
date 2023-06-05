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
#include "play_info_holder.h"
#include "avcast_control_command.h"
#include "avsession_info.h"

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class IAVCastControllerProxy {
public:
    virtual void Init() = 0;

    virtual void release() = 0;

    virtual void RegisterControllerListener(const IAVCastSessionStateListener iAVCastSessionStateListener) = 0;

    virtual void UnregisterControllerListener(const IAVCastSessionStateListener iAVCastSessionStateListener) = 0;

    virtual void Start(const PlayInfoHolder& playInfoHolder) = 0;

    virtual void SendControlCommand(const AVCastControlCommand& cmd) = 0;





};
} // namespace OHOS::AVSession
#endif // OHOS_I_AVCAST_CONTROLLER_PROXY_H
