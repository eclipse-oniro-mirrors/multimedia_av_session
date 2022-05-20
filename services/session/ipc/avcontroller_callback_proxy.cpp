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

#include "avcontroller_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControllerCallbackProxy::AVControllerCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVControllerCallback>(impl)
{
    SLOGD("construct");
}

void AVControllerCallbackProxy::OnVolumeInfoChange(const AVVolumeInfo &volumeInfo)
{
}

void AVControllerCallbackProxy::OnSessionRelease(const AVSessionDescriptor &descriptor)
{
}

void AVControllerCallbackProxy::OnPlaybackStateUpdate(const AVPlaybackState &state)
{
}

void AVControllerCallbackProxy::OnMetaDataUpdate(const AVMetaData &data)
{
}

void AVControllerCallbackProxy::OnActiveStateChange(bool isActive)
{
    MessageParcel data;
    CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(data.WriteBool(isActive), "write bool failed");

    MessageParcel reply;
    MessageOption option;
    CHECK_AND_PRINT_LOG(Remote()->SendRequest(CONTROLLER_CMD_ON_ACTIVE_STATE_CHANGE, data, reply, option) == 0,
                        "send request failed");
}
}