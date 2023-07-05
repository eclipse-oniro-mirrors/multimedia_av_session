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

#include "remote_session_command_process.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
RemoteSessionCommandProcess::RemoteSessionCommandProcess(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSessionService>(impl)
{
    SLOGD("constructor");
}

int32_t RemoteSessionCommandProcess::ProcessCastAudioCommand(const RemoteServiceCommand command,
                                                             const std::string& input, std::string& output)
{
    AVSESSION_TRACE_SYNC_START("AVSessionServiceProxy::ProcessCastAudioCommand");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(command), ERR_MARSHALLING, "write command failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(input), ERR_MARSHALLING, "write input failed");
    MessageParcel reply;
    MessageOption option;
    CHECK_AND_RETURN_RET_LOG(Remote()->SendRequest(
        static_cast<uint32_t>(AvsessionSeviceInterfaceCode::SERVICE_CMD_SEND_COMMAND_TO_REMOTE),\
        data, reply, option) == 0,
        ERR_RPC_SEND_REQUEST, "send request failed");
    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_MARSHALLING, "read reply failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "send remote request failed");
    CHECK_AND_RETURN_RET_LOG(reply.ReadString(output), ERR_MARSHALLING, "read output failed");
    return AVSESSION_SUCCESS;
}
}