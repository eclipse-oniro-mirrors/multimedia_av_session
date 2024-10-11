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

#ifndef OHOS_IAVSESSION_SERVICE_INTERFACE_H
#define OHOS_IAVSESSION_SERVICE_INTERFACE_H

#include "iav_session.h"

/* SAID: 3010 */
namespace OHOS::AVSession {
enum class AvsessionSeviceInterfaceCode {
    SERVICE_CMD_CREATE_SESSION,
    SERVICE_CMD_GET_ALL_SESSION_DESCRIPTORS,
    SERVICE_CMD_GET_SESSION_DESCRIPTORS_BY_ID,
    SERVICE_CMD_GET_HISTORY_SESSION_DESCRIPTORS,
    SERVICE_CMD_GET_HISTORY_AVQUEUE_INFOS,
    SERVICE_CMD_START_AV_PLAYBACK,
    SERVICE_CMD_CREATE_CONTROLLER,
    SERVICE_CMD_GET_AV_CAST_CONTROLLER,
    SERVICE_CMD_REGISTER_SESSION_LISTENER,
    SERVICE_CMD_REGISTER_SESSION_LISTENER_FOR_ALL_USERS,
    SERVICE_CMD_SEND_SYSTEM_AV_KEY_EVENT,
    SERVICE_CMD_SEND_SYSTEM_CONTROL_COMMAND,
    SERVICE_CMD_REGISTER_CLIENT_DEATH,
    SERVICE_CMD_CAST_AUDIO,
    SERVICE_CMD_CAST_AUDIO_FOR_ALL,
    SERVICE_CMD_SEND_COMMAND_TO_REMOTE,
    SERVICE_CMD_START_CAST_DISCOVERY,
    SERVICE_CMD_STOP_CAST_DISCOVERY,
    SERVICE_CMD_START_DEVICE_LOGGING,
    SERVICE_CMD_STOP_DEVICE_LOGGING,
    SERVICE_CMD_SET_DISCOVERYABLE,
    SERVICE_CMD_START_CAST,
    SERVICE_CMD_STOP_CAST,
    SERVICE_CMD_CLOSE,
    SERVICE_CMD_CHECK_BACKGROUND_ALLOWED,
    SERVICE_CMD_MAX
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_SERVICE_INTERFACE_H