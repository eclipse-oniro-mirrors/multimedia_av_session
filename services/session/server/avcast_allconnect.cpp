/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avcast_allconnect.h"

namespace OHOS::AVSession {
CastAllConnectCallback::CastAllConnectCallback(IAVSessionServiceListener *servicePtr)
{
    SLOGI("CastAllConnectCallback constructor");
    {
        servicePtr_ = servicePtr;
    }
}

CastAllConnectCallback::~CastAllConnectCallback()
{
    SLOGI("CastAllConnectCallback destruct");
}

int32_t CastAllConnectCallback::OnServiceStateChanged(std::string deviceId,
    std::string serviceName, std::string extraInfo, int32_t state, int pid)
{
    SLOGI("deviceId = %{public}s, serviceName = %{public}s, state = %{public}d",
        deviceId.c_str(), serviceName.c_str(), state);
    serviceNameMapState_[serviceName] = state;
    servicePtr_->NotifyMirrorToStreamCast();
    return AVSESSION_SUCCESS;
}

int32_t CastAllConnectCallback::GetCastAllConnectData(std::map<std::string, int32_t>& serviceNameMapState)
{
    serviceNameMapState = serviceNameMapState_;
    return AVSESSION_SUCCESS;
}

}