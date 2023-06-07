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

#include "session_listener_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
SessionListenerProxy::SessionListenerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<ISessionListener>(impl)
{
    SLOGD("construct");
}

void SessionListenerProxy::OnSessionCreate(const AVSessionDescriptor& descriptor)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(descriptor.WriteToParcel(data), "write descriptor failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(LISTENER_CMD_ON_CREATE, data, reply, option) == 0, "send request fail");
}

void SessionListenerProxy::OnSessionRelease(const AVSessionDescriptor& descriptor)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(descriptor.WriteToParcel(data), "write descriptor failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(LISTENER_CMD_ON_RELEASE, data, reply, option) == 0, "send request fail");
}

void SessionListenerProxy::OnTopSessionChange(const AVSessionDescriptor& descriptor)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(descriptor.WriteToParcel(data), "write descriptor failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(LISTENER_CMD_TOP_CHANGED, data, reply, option) == 0, "send request fail");
}

void SessionListenerProxy::OnAudioSessionChecked(const int32_t uid)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteInt32(uid), "write uid failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(LISTENER_CMD_AUDIO_CHECKED, data, reply, option) == 0,
        "send request fail");
}

void SessionListenerProxy::OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(castOutputDeviceInfo.WriteToParcel(data), "write castOutputDeviceInfo failed");

    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    CHECK_AND_RETURN_LOG(remote->SendRequest(LISTENER_CMD_DEVICE_FOUND, data, reply, option) == 0,
        "send request fail");
}
} // namespace OHOS::AVSession
