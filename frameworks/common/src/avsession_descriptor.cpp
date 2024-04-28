/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

    int32_t deviceInfoSize = static_cast<int32_t>(outputDeviceInfo_.deviceInfos_.size());
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (DeviceInfo deviceInfo : outputDeviceInfo_.deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.castCategory_), false, "write castCategory failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceId_), false, "write deviceId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceName_), false, "write deviceName failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.deviceType_), false, "write deviceType failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.ipAddress_), false, "write ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.providerId_), false, "write providerId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.supportedProtocols_), false,
            "write supportedProtocols failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.authenticationStatus_), false,
            "write authenticationStatus failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.supportedDrmCapabilities_.size()), false,
            "write supportedDrmCapabilities size failed");
        for (auto supportedDrmCapability : deviceInfo.supportedDrmCapabilities_) {
            CHECK_AND_RETURN_RET_LOG(out.WriteString(supportedDrmCapability), false,
                "write supportedDrmCapability failed");
        }
    }
    CHECK_AND_RETURN_RET_LOG(out.WriteParcelable(&elementName_), false, "write elementName failed");
    return true;
}

bool AVSessionDescriptor::CheckBeforReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionId_), false, "Read sessionId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(sessionType_), false, "Read sessionType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionTag_), false, "Read sessionTag failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(pid_), false, "Read pid failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(uid_), false, "Read uid failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isActive_), false, "Read isActive failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isTopSession_), false, "Read isTopSession failed");
    return true;
}

bool AVSessionDescriptor::CheckBeforReadFromParcel(Parcel& in, DeviceInfo& deviceInfo)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.castCategory_), false, "Read castCategory failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.deviceId_), false, "Read deviceId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.deviceName_), false, "Read deviceName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.deviceType_), false, "Read deviceType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.ipAddress_), false, "Read ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.providerId_), false, "Read providerId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.supportedProtocols_), false,
        "Read supportedProtocols failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.authenticationStatus_), false,
        "Read authenticationStatus failed");
    int32_t supportedDrmCapabilityLen = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedDrmCapabilityLen), false,
        "read supportedDrmCapabilityLen failed");
    int32_t maxSupportedDrmCapabilityLen = 10;
    CHECK_AND_RETURN_RET_LOG((supportedDrmCapabilityLen >= 0) &&
        (supportedDrmCapabilityLen <= maxSupportedDrmCapabilityLen), false, "supportedDrmCapabilityLen is illegal");
    std::vector<std::string> supportedDrmCapabilities;
    for (int i = 0; i < supportedDrmCapabilityLen; i++) {
        std::string supportedDrmCapability;
        CHECK_AND_RETURN_RET_LOG(in.ReadString(supportedDrmCapability), false,
            "read supportedDrmCapability failed");
        supportedDrmCapabilities.emplace_back(supportedDrmCapability);
    }
    deviceInfo.supportedDrmCapabilities_ = supportedDrmCapabilities;
    outputDeviceInfo_.deviceInfos_.emplace_back(deviceInfo);
    return true;
}

bool AVSessionDescriptor::ReadFromParcel(Parcel& in)
{
    if (!CheckBeforReadFromParcel(in)) {
        return false;
    }
    int32_t deviceInfoSize;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (int i = 0; i < deviceInfoSize; i++) {
        DeviceInfo deviceInfo;
        if (!CheckBeforReadFromParcel(in, deviceInfo)) {
            return false;
        }  
    }

    sptr elementName = in.ReadParcelable<AppExecFwk::ElementName>();
    if (elementName == nullptr) {
        SLOGE("read element name failed");
        return false;
    }
    elementName_ = *elementName;
    return true;
}

bool DeviceInfo::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(castCategory_), false, "write castCategory failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceId_), false, "write deviceId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceName_), false, "write deviceName failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceType_), false, "write deviceType failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(ipAddress_), false, "write ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(providerId_), false, "write providerId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(supportedProtocols_), false,
        "write supportedProtocols failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(authenticationStatus_), false,
        "write authenticationStatus failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(supportedDrmCapabilities_.size()), false,
        "write supportedDrmCapabilities size failed");
    for (auto supportedDrmCapability : supportedDrmCapabilities_) {
        CHECK_AND_RETURN_RET_LOG(out.WriteString(supportedDrmCapability), false,
            "write supportedDrmCapability failed");
    }

    return true;
}

bool DeviceInfo::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(castCategory_), false, "Read castCategory failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceId_), false, "Read deviceId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceName_), false, "Read deviceName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceType_), false, "Read deviceType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(ipAddress_), false, "Read ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(providerId_), false, "Read providerId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedProtocols_), false,
        "Read supportedProtocols failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(authenticationStatus_), false,
        "Read authenticationStatus failed");
    int32_t supportedDrmCapabilityLen = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedDrmCapabilityLen), false,
        "read supportedDrmCapabilityLen failed");
    int32_t maxSupportedDrmCapabilityLen = 10;
    CHECK_AND_RETURN_RET_LOG((supportedDrmCapabilityLen >= 0) &&
        (supportedDrmCapabilityLen <= maxSupportedDrmCapabilityLen), false, "supportedDrmCapabilityLen is illegal");
    std::vector<std::string> supportedDrmCapabilities;
    for (int i = 0; i < supportedDrmCapabilityLen; i++) {
        std::string supportedDrmCapability;
        CHECK_AND_RETURN_RET_LOG(in.ReadString(supportedDrmCapability), false,
            "read supportedDrmCapability failed");
        supportedDrmCapabilities.emplace_back(supportedDrmCapability);
    }
    supportedDrmCapabilities_ = supportedDrmCapabilities;

    return true;
}

bool OutputDeviceInfo::WriteToParcel(Parcel& out) const
{
    int32_t deviceInfoSize = static_cast<int32_t>(deviceInfos_.size());
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    for (DeviceInfo deviceInfo : deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.castCategory_), false, "write castCategory failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceId_), false, "write deviceId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceName_), false, "write deviceName failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.deviceType_), false, "write deviceType failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.ipAddress_), false, "write ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.providerId_), false, "write providerId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.supportedProtocols_), false,
            "Read supportedProtocols failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.authenticationStatus_), false,
            "Read authenticationStatus failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.supportedDrmCapabilities_.size()), false,
            "write supportedDrmCapabilities size failed");
        for (auto supportedDrmCapability : deviceInfo.supportedDrmCapabilities_) {
            CHECK_AND_RETURN_RET_LOG(out.WriteString(supportedDrmCapability), false,
                "write supportedDrmCapability failed");
        }
    }
    return true;
}

bool OutputDeviceInfo::ReadFromParcel(Parcel& in)
{
    int32_t deviceInfoSize;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (int i = 0; i < deviceInfoSize; i++) {
        DeviceInfo deviceInfo;
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.castCategory_), false, "Read castCategory failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.deviceId_), false, "Read deviceId failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.deviceName_), false, "Read deviceName failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.deviceType_), false, "Read deviceType failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.ipAddress_), false, "Read ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.providerId_), false, "Read providerId failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.supportedProtocols_), false,
            "Read supportedProtocols failed");
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.authenticationStatus_), false,
            "Read authenticationStatus failed");
        int32_t supportedDrmCapabilityLen = 0;
        CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedDrmCapabilityLen), false,
            "read supportedDrmCapabilityLen failed");
        int32_t maxSupportedDrmCapabilityLen = 10;
        CHECK_AND_RETURN_RET_LOG((supportedDrmCapabilityLen >= 0) &&
            (supportedDrmCapabilityLen <= maxSupportedDrmCapabilityLen), false, "supportedDrmCapabilityLen is illegal");
        std::vector<std::string> supportedDrmCapabilities;
        for (int i = 0; i < supportedDrmCapabilityLen; i++) {
            std::string supportedDrmCapability;
            CHECK_AND_RETURN_RET_LOG(in.ReadString(supportedDrmCapability), false,
                "read supportedDrmCapability failed");
            supportedDrmCapabilities.emplace_back(supportedDrmCapability);
        }
        deviceInfo.supportedDrmCapabilities_ = supportedDrmCapabilities;
        deviceInfos_.emplace_back(deviceInfo);
    }
    return true;
}
} // namespace OHOS::AVSession
