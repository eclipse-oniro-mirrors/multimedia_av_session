/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "command_info.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
CommandInfo::CommandInfo()
{
}

CommandInfo::~CommandInfo()
{
}

void CommandInfo::Unmarshalling(Parcel& data)
{
    SetDeviceId(data.ReadString());
    SetBundleName(data.ReadString());
    SetModuleName(data.ReadString());
    SetPlayType(data.ReadString());
}

bool CommandInfo::Marshalling(Parcel& parcel) const
{
    auto WriteCommonSessionParams = [&parcel, this]() -> bool {
        return parcel.WriteString(deviceId_) &&
               parcel.WriteString(bundleName_) &&
               parcel.WriteString(moduleName_) &&
               parcel.WriteString(playType_);
    };

    CHECK_AND_RETURN_RET_LOG(WriteCommonSessionParams(), false, "write common info failed");
    return true;
}

// LCOV_EXCL_START
int32_t CommandInfo::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
    return AVSESSION_SUCCESS;
}

int32_t CommandInfo::GetDeviceId(std::string& deviceId) const
{
    deviceId = deviceId_;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t CommandInfo::SetBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
    return AVSESSION_SUCCESS;
}

int32_t CommandInfo::GetBundleName(std::string& bundleName) const
{
    bundleName = bundleName_;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t CommandInfo::SetModuleName(const std::string& moduleName)
{
    moduleName_ = moduleName;
    return AVSESSION_SUCCESS;
}

int32_t CommandInfo::GetModuleName(std::string& moduleName) const
{
    moduleName = moduleName_;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t CommandInfo::SetPlayType(const std::string& playType)
{
    playType_ = playType;
    return AVSESSION_SUCCESS;
}

int32_t CommandInfo::GetPlayType(std::string& playType) const
{
    playType = playType_;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
