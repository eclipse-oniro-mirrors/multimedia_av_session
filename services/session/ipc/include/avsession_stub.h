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

#ifndef OHOS_AVSESSION_STUB_H
#define OHOS_AVSESSION_STUB_H

#include "iav_session.h"
#include "iremote_stub.h"
#include "want_agent.h"
#include "avsession_log.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
class AVSessionStub : public IRemoteStub<IAVSession> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(std::shared_ptr<AVSessionCallback>& callback) override
    {
        return ERR_NONE;
    }

private:
    int32_t HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetController(MessageParcel& data, MessageParcel& reply);

    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDisactive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleIsActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleRelease(MessageParcel& data, MessageParcel& reply);

    int32_t HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int32_t(AVSessionStub::*)(MessageParcel&, MessageParcel&);
    static inline HanlerFunc handlers[] = {
        [SESSION_CMD_GET_SESSION_ID] = &AVSessionStub::HandleGetSessionId,
        [SESSION_CMD_GET_META_DATA] = &AVSessionStub::HandleGetAVMetaData,
        [SESSION_CMD_SET_META_DATA] = &AVSessionStub::HandleSetAVMetaData,
        [SESSION_CMD_GET_PLAYBACK_STATE] = &AVSessionStub::HandleGetAVPlaybackState,
        [SESSION_CMD_SET_PLAYBACK_STATE] = &AVSessionStub::HandleSetAVPlaybackState,
        [SESSION_CMD_SET_LAUNCH_ABILITY] = &AVSessionStub::HandleSetLaunchAbility,
        [SESSION_CMD_GET_CONTROLLER] = &AVSessionStub::HandleGetController,
        [SESSION_CMD_REGISTER_CALLBACK] = &AVSessionStub::HandleRegisterCallbackInner,
        [SESSION_CMD_ACTIVE] = &AVSessionStub::HandleActive,
        [SESSION_CMD_DISACTIVE] = &AVSessionStub::HandleDisactive,
        [SESSION_CMD_ISACTIVE] = &AVSessionStub::HandleIsActive,
        [SESSION_CMD_RELEASE] = &AVSessionStub::HandleRelease,
        [SESSION_CMD_ADDSUPPORT_COMMAND] = &AVSessionStub::HandleAddSupportCommand,
    };
};
}
#endif // OHOS_AVSESSION_STUB_H