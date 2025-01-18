/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "migrate_avsession_proxy.h"

#include "avsession_log.h"
#include "softbus/softbus_session_utils.h"

namespace OHOS::AVSession {
void MigrateAVSessionProxy::OnConnectServer(const std::string &deviceId)
{
    SLOGI("OnConnectServer: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
}

void MigrateAVSessionProxy::OnDisconnectServer(const std::string &deviceId)
{
    SLOGI("OnDisconnectServer: %{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
}

int32_t MigrateAVSessionProxy::GetCharacteristic()
{
    return mMode_;
}

//LCOV_EXCL_START
void MigrateAVSessionProxy::OnBytesReceived(const std::string &deviceId, const std::string &data)
{
    SLOGI("OnBytesReceived: %{public}s", data.c_str());
}
//LCOV_EXCL_STOP

} // namespace OHOS::AVSession