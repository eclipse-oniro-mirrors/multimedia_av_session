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

#ifndef OHOS_AVSESSION_SERVICE_STUB_H
#define OHOS_AVSESSION_SERVICE_STUB_H

#include "iavsession_service.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionServiceStub : public IRemoteStub<IAVSessionService> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int HandleCreateSession(MessageParcel &data, MessageParcel &reply);

    int HandleRegisterSessionListener(MessageParcel &data, MessageParcel &reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HanlerFunc = int(AVSessionServiceStub::*)(MessageParcel&, MessageParcel&);
    static inline HanlerFunc handlers[] = {
        [SERVICE_CMD_CREATE_TABLE] = &AVSessionServiceStub::HandleCreateSession,
        [SERVICE_CMD_REGISTER_SESSION_LISTENER] = &AVSessionServiceStub::HandleRegisterSessionListener,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVICE_STUB_H