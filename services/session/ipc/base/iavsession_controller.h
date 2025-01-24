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

#ifndef OHOS_IAVSESSION_CONTROLLER_H
#define OHOS_IAVSESSION_CONTROLLER_H

#include "avsession_controller.h"
#include "iavcontroller_callback.h"
#include "iremote_broker.h"

namespace OHOS::AVSession {
class IAVSessionController : public AVSessionController, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVSessionController");

    enum {
        CONTROLLER_CMD_REGISTER_CALLBACK,
        CONTROLLER_CMD_DESTROY,
        CONTROLLER_CMD_GET_AV_PLAYBACK_STATE,
        CONTROLLER_CMD_GET_AV_META_DATA,
        CONTROLLER_CMD_SEND_AV_KEYEVENT,
        CONTROLLER_CMD_GET_LAUNCH_ABILITY,
        CONTROLLER_CMD_GET_VALID_COMMANDS,
        CONTROLLER_CMD_SEND_CONTROL_COMMAND,
        CONTROLLER_CMD_SEND_COMMON_COMMAND,
        CONTROLLER_CMD_SET_META_FILTER,
        CONTROLLER_CMD_SET_PLAYBACK_FILTER,
        CONTROLLER_CMD_IS_SESSION_ACTIVE,
        CONTROLLER_CMD_GET_SESSION_ID,
        CONTROLLER_CMD_GET_AV_QUEUE_ITEMS,
        CONTROLLER_CMD_GET_AV_QUEUE_TITLE,
        CONTROLLER_CMD_SKIP_TO_QUEUE_ITEM,
        CONTROLLER_CMD_GET_EXTRAS,
        CONTROLLER_CMD_GET_EXTRAS_WITH_EVENT,
        CONTROLLER_CMD_GET_AVCALL_META_DATA,
        CONTROLLER_CMD_SET_AVCALL_META_FILTER,
        CONTROLLER_CMD_GET_AVCALL_STATE,
        CONTROLLER_CMD_SET_AVCALL_STATE_FILTER,
        CONTROLLER_CMD_MAX,
    };

protected:
    virtual int32_t RegisterCallbackInner(const sptr<IRemoteObject>& callback) = 0;
};
}
#endif // OHOS_IAVSESSION_CONTROLLER_H