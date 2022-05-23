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

#include "avsession_proxy.h"
#include "avplayback_state.h"

namespace OHOS::AVSession {
AVSessionProxy::AVSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSession>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionProxy::GetSessionId()
{
    return 0;
}

int32_t AVSessionProxy::RegisterCallback(std::shared_ptr<AVSessionCallback> &callback)
{
    sptr<IRemoteObject> object;
    RegisterCallbackInner(object);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::RegisterCallbackInner(sptr<IRemoteObject> &callback)
{
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::Release()
{
    SLOGD("enter");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::SetAVMetaData(const AVMetaData& meta)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(AVSessionProxy::GetDescriptor())) {
        SLOGE("Failed to write descriptor");
        return AVSESSION_SUCCESS;
    }

    int32_t ret = Remote()->SendRequest(SESSION_CMD_SET_META_DATA, data, reply, option);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("Init parameter failed, error: %{public}d", ret);
        return ret;
    }
    return reply.ReadInt32();
}

int32_t AVSessionProxy::GetAVPlaybackState(AVPlaybackState& state)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(AVSessionProxy::GetDescriptor())) {
        SLOGE("Failed to write descriptor");
        return AVSESSION_ERROR;
    }

    data.WriteInt32(static_cast<int32_t>(state.GetState()));
    data.WriteInt64(state.GetBufferedTime());

    int32_t ret = Remote()->SendRequest(SESSION_CMD_GET_PLAYBACK_STATE, data, reply, option);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("Init parameter failed, error: %{public}d", ret);
        return ret;
    }
    return reply.ReadInt32();
}

int32_t AVSessionProxy::GetAVMetaData(AVMetaData& meta)
{
    return 0;
}

int32_t AVSessionProxy::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    return 0;
}

std::shared_ptr<AVSessionController> AVSessionProxy::GetController()
{
    return nullptr;
}

int32_t AVSessionProxy::Active()
{
    return 0;
}

int32_t AVSessionProxy::Disactive()
{
    return 0;
}

bool AVSessionProxy::IsActive()
{
    return false;
}


int32_t AVSessionProxy::AddSupportCommand(const std::string& cmd)
{
    return 0;
}
}