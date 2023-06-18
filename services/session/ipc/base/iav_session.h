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

#ifndef OHOS_IAVSESSION_H
#define OHOS_IAVSESSION_H

#include "iremote_broker.h"
#include "av_session.h"
#include "iavsession_callback.h"

namespace OHOS::AVSession {
class IAVSession : public AVSession, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.avsession.IAVSession");

    enum {
        SESSION_CMD_GET_SESSION_ID,
        SESSION_CMD_GET_SESSION_TYPE,
        SESSION_CMD_GET_META_DATA,
        SESSION_CMD_SET_META_DATA,
        SESSION_CMD_GET_PLAYBACK_STATE,
        SESSION_CMD_SET_PLAYBACK_STATE,
        SESSION_CMD_GET_QUEUE_ITEMS,
        SESSION_CMD_SET_QUEUE_ITEMS,
        SESSION_CMD_GET_QUEUE_TITLE,
        SESSION_CMD_SET_QUEUE_TITLE,
        SESSION_CMD_GET_EXTRAS,
        SESSION_CMD_SET_EXTRAS,
        SESSION_CMD_SET_LAUNCH_ABILITY,
        SESSION_CMD_GET_CONTROLLER,
        SESSION_CMD_GET_AVCAST_CONTROLLER,
        SESSION_CMD_REGISTER_CALLBACK,
        SESSION_CMD_ACTIVATE,
        SESSION_CMD_DEACTIVATE,
        SESSION_CMD_ISACTIVE,
        SESSION_CMD_DESTROY,
        SESSION_CMD_ADD_SUPPORT_COMMAND,
        SESSION_CMD_DELETE_SUPPORT_COMMAND,
        SESSION_CMD_SET_SESSION_EVENT,
        SESSION_CMD_RELEASE_CAST,
        SESSION_CMD_MAX,
    };

protected:
    virtual int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) = 0;
    virtual sptr<IRemoteObject> GetControllerInner() = 0;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    virtual sptr<IRemoteObject> GetAVCastControllerInner() = 0;
#endif
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_H