/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
        SESSION_CMD_GET_META_DATA,
        SESSION_CMD_SET_META_DATA,
        SESSION_CMD_GET_PLAYBACK_STATE,
        SESSION_CMD_SET_PLAYBACK_STATE,
        SESSION_CMD_SET_LAUNCH_ABILITY,
        SESSION_CMD_GET_CONTROLLER,
        SESSION_CMD_REGISTER_CALLBACK,
        SESSION_CMD_ACTIVE,
        SESSION_CMD_DISACTIVE,
        SESSION_CMD_ISACTIVE,
        SESSION_CMD_RELEASE,
        SESSION_CMD_ADDSUPPORT_COMMAND,
        SESSION_CMD_MAX,
    };

protected:
    virtual int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_IAVSESSION_H