/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "avsession_service_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_proxy.h"

namespace OHOS::AVSession {
AVSessionServiceProxy::AVSessionServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSessionService>(impl)
{
    SLOGD("constructor");
}

std::shared_ptr<AVSession> AVSessionServiceProxy::CreateSession(const std::string &tag)
{
    auto object = CreateSessionInner(tag);
    auto session = iface_cast<AVSessionProxy>(object);
    return std::shared_ptr<AVSession>(session.GetRefPtr(), [holder = session](const auto*) {});
}

sptr<IRemoteObject> AVSessionServiceProxy::CreateSessionInner(const std::string &tag)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), nullptr, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(tag), nullptr, "write tag failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_CREATE_TABLE, data, reply, option),
                             nullptr, "send request failed");
    return reply.ReadRemoteObject();
}

int32_t AVSessionServiceProxy::RegisterSessionListener(const sptr<ISessionListener> &remoteObject)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(remoteObject->AsObject()), ERR_MARSHALLING, "write tag failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(SERVICE_CMD_REGISTER_SESSION_LISTENER, data, reply, option),
                             ERR_IPC_SEND_REQUEST, "send request failed");
    int32_t res = AVSESSION_ERROR;
    return reply.ReadInt32(res) ? res : AVSESSION_ERROR;
}
} // namespace OHOS