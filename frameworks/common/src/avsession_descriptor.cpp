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

#include "avsession_descriptor.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVHistoryDescriptor::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteString(sessionId_), false, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(bundleName_), false, "write bundleName failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(abilityName_), false, "write abilityName failed");
    return true;
}

bool AVHistoryDescriptor::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionId_), false, "Read sessionId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(bundleName_), false, "Read bundleName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(abilityName_), false, "Read abilityName failed");
    return true;
}

bool AVSessionDescriptor::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteString(sessionId_), false, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(sessionType_), false, "write sessionType failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(sessionTag_), false, "write sessionTag failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(pid_), false, "write pid failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(uid_), false, "write uid failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(isActive_), false, "write isActive failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(isTopSession_), false, "write isTopSession failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(outputDeviceInfo_.isRemote_), false, "write isRemote failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteStringVector(outputDeviceInfo_.deviceIds_), false, "write deviceIds failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteStringVector(outputDeviceInfo_.deviceNames_), false, "write deviceNames failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteParcelable(&elementName_), false, "write elementName failed");
    return true;
}

bool AVSessionDescriptor::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionId_), false, "Read sessionId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(sessionType_), false, "Read sessionType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionTag_), false, "Read sessionTag failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(pid_), false, "Read pid failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(uid_), false, "Read uid failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isActive_), false, "Read isActive failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isTopSession_), false, "Read isTopSession failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(outputDeviceInfo_.isRemote_), false, "Read isRemote failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadStringVector(&outputDeviceInfo_.deviceIds_), false, "Read deviceIds failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadStringVector(&outputDeviceInfo_.deviceNames_), false, "Read deviceNames failed");

    sptr elementName = in.ReadParcelable<AppExecFwk::ElementName>();
    if (elementName == nullptr) {
        SLOGE("read element name failed");
        return false;
    }
    elementName_ = *elementName;
    return true;
}

bool CastDeviceInfo::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceCategory_), false, "write deviceCategory failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceId_), false, "write deviceId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceName_), false, "write deviceName failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceType_), false, "write deviceType failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(ipAddress_), false, "write ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(providerId_), false, "write providerId failed");

    return true;
}

bool CastDeviceInfo::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceCategory_), false, "Read deviceCategory failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceId_), false, "Read deviceId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceName_), false, "Read deviceName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceType_), false, "Read deviceType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(ipAddress_), false, "Read ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(providerId_), false, "Read providerId failed");

    return true;
}

bool CastOutputDeviceInfo::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(castDevices_.size()), false, "write castDevices size failed");
    for (CastDeviceInfo castDevice : castDevices_) {
        castDevice.WriteToParcel(out);
    }
    return true;
}

bool CastOutputDeviceInfo::ReadFromParcel(Parcel& in)
{
    int32_t castDevicesSize;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(castDevicesSize), false, "Read castDevices size failed");
    for (int i = 0; i < castDevicesSize; i++) {
        CastDeviceInfo castDevice;
        castDevice.ReadFromParcel(in);
        castDevices_.emplace_back(castDevice);
    }
    return true;
}
} // namespace OHOS::AVSession
