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

#include "iavsession.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionStub : public IRemoteStub<IAVSession> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(std::shared_ptr<AVSessionCallback>& callback) override
    {
        return 0;
    };

private:
    int HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    int HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int HandleRelease(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int(AVSessionStub::*)(MessageParcel&, MessageParcel&);
    static inline HanlerFunc handlers[] = {
        [SESSION_CMD_GET_SESSION_ID] = &AVSessionStub::HandleGetSessionId,
        [SESSION_CMD_REGISTER_CALLBACK] = &AVSessionStub::HandleRegisterCallbackInner,
        [SESSION_CMD_RELEASE] = &AVSessionStub::HandleRelease,
    };
};
}
#endif // OHOS_AVSESSION_STUB_H