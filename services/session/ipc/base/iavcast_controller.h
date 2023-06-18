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

#ifndef OHOS_IAVCAST_CONTROLLER_H
#define OHOS_IAVCAST_CONTROLLER_H

#include "avcast_controller.h"
#include "iavcontroller_callback.h"
#include "iremote_broker.h"

namespace OHOS::AVSession {
class IAVCastController : public AVCastController, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVCastController");

    enum {
        CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND,
        CAST_CONTROLLER_CMD_START,
        CAST_CONTROLLER_CMD_UPDATE,
        CAST_CONTROLLER_CMD_GET_DURATION,
        CAST_CONTROLLER_CMD_GET_POSITION,
        CAST_CONTROLLER_CMD_GET_VOLUME,
        CAST_CONTROLLER_CMD_GET_LOOP_MODE,
        CAST_CONTROLLER_CMD_GET_PLAY_SPEED,
        CAST_CONTROLLER_CMD_GET_PLAY_STATE,
        CAST_CONTROLLER_CMD_SET_DISPLAY_SURFACE,
        CAST_CONTROLLER_CMD_REGISTER_CALLBACK,
        CAST_CONTROLLER_CMD_DESTROY,
        CAST_CONTROLLER_CMD_MAX,
    };

protected:
    virtual int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) = 0;
};
}
#endif // OHOS_IAVCAST_CONTROLLER_H
