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

#ifndef OHOS_IAVCAST_CONTROLLER_CALLBACK_H
#define OHOS_IAVCAST_CONTROLLER_CALLBACK_H

#include "avsession_info.h"
#include "iremote_broker.h"

namespace OHOS::AVSession {
class IAVCastControllerCallback : public AVCastControllerCallback, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVCastControllerCallback");

    enum {
        CAST_CONTROLLER_CMD_ON_STATE_CHANGE,
        CAST_CONTROLLER_CMD_ON_MEDIA_ITEM_CHANGE,
        CAST_CONTROLLER_CMD_ON_VOLUME_CHANGE,
        CAST_CONTROLLER_CMD_ON_LOOP_MODE_CHANGE,
        CAST_CONTROLLER_CMD_ON_PLAY_SPEED_CHANGE,
        CAST_CONTROLLER_CMD_ON_POSITION_CHANGE,
        CAST_CONTROLLER_CMD_ON_VIDEO_SIZE_CHANGE,
        CAST_CONTROLLER_CMD_ON_ERROR,
        CAST_CONTROLLER_CMD_MAX,
    };
};
}
#endif // OHOS_IAVCAST_CONTROLLER_CALLBACK_H
