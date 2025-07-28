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

#include "avsession_descriptor.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVHistoryDescriptor::Marshalling(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteString(sessionId_), false, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(bundleName_), false, "write bundleName failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(abilityName_), false, "write abilityName failed");
    return true;
}

AVHistoryDescriptor* AVHistoryDescriptor::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<AVHistoryDescriptor>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->ReadFromParcel(in), nullptr, "info is nullptr");
    return info.release();
}

bool AVHistoryDescriptor::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionId_), false, "Read sessionId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(bundleName_), false, "Read bundleName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(abilityName_), false, "Read abilityName failed");
    return true;
}

bool AVSessionDescriptor::Marshalling(Parcel& out) const
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
    for (DeviceInfo deviceInfo : outputDeviceInfo_.deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.castCategory_), false, "write castCategory failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceId_), false, "write deviceId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.deviceName_), false, "write deviceName failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.deviceType_), false, "write deviceType failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.ipAddress_), false, "write ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.networkId_), false, "write networkId failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.manufacturer_), false, "write manufacturer failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceInfo.modelName_), false, "write modelName failed");
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
        CHECK_AND_RETURN_RET_LOG(out.WriteBool(deviceInfo.isLegacy_), false, "write isLegacy failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.mediumTypes_), false, "write mediumTypes failed");
        CHECK_AND_RETURN_RET_LOG(deviceInfo.audioCapabilities_.WriteToParcel(out), false,
            "write audioCapability failed");
        CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfo.supportedPullClients_.size()), false,
            "write supportedPullClients size failed");
        for (auto supportedPullClient : deviceInfo.supportedPullClients_) {
            CHECK_AND_RETURN_RET_LOG(out.WriteUint32(supportedPullClient), false,
                "write supportedPullClient failed");
        }
    }
    CHECK_AND_RETURN_RET_LOG(out.WriteParcelable(&elementName_), false, "write elementName failed");
    return true;
}

AVSessionDescriptor* AVSessionDescriptor::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<AVSessionDescriptor>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->ReadFromParcel(in), nullptr, "info is nullptr");
    return info.release();
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
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.networkId_), false, "Read networkId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.manufacturer_), false, "Read manufacturer failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceInfo.modelName_), false, "Read modelName failed");
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
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(deviceInfo.isLegacy_), false, "Read isLegacy failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfo.mediumTypes_), false, "Read mediumTypes failed");
    CHECK_AND_RETURN_RET_LOG(deviceInfo.audioCapabilities_.ReadFromParcel(in), false, "Read audioCapability failed");

    int32_t supportedPullClientsLen = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedPullClientsLen), false, "read supportedPullClientsLen failed");
    // max length of the clients vector
    int32_t maxSupportedPullClientsLen = 256;
    CHECK_AND_RETURN_RET_LOG((supportedPullClientsLen >= 0) &&
        (supportedPullClientsLen <= maxSupportedPullClientsLen), false, "supportedPullClientsLen is illegal");
    std::vector<std::uint32_t> supportedPullClients;
    for (int j = 0; j < supportedPullClientsLen; j++) {
        uint32_t supportedPullClient = 0;
        CHECK_AND_RETURN_RET_LOG(in.ReadUint32(supportedPullClient), false,
            "read supportedPullClient failed");
        supportedPullClients.emplace_back(supportedPullClient);
    }
    deviceInfo.supportedPullClients_ = supportedPullClients;
    outputDeviceInfo_.deviceInfos_.emplace_back(deviceInfo);
    return true;
}

bool AVSessionDescriptor::ReadFromParcel(Parcel& in)
{
    if (!CheckBeforReadFromParcel(in)) {
        return false;
    }
    int32_t deviceInfoSize = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfoSize), false, "read deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (int j = 0; j < deviceInfoSize; j++) {
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

bool DeviceInfo::Marshalling(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(castCategory_), false, "write castCategory failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceId_), false, "write deviceId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(deviceName_), false, "write deviceName failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceType_), false, "write deviceType failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(ipAddress_), false, "write ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(networkId_), false, "write networkId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(manufacturer_), false, "write manufacturer failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(modelName_), false, "write modelName failed");
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
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(isLegacy_), false, "write isLegacy failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(mediumTypes_), false, "write mediumTypes failed");
    CHECK_AND_RETURN_RET_LOG(audioCapabilities_.WriteToParcel(out), false, "write audioCapability failed");

    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(supportedPullClients_.size()), false,
        "write supportedPullClients size failed");
    for (auto supportedPullClient : supportedPullClients_) {
        CHECK_AND_RETURN_RET_LOG(out.WriteUint32(supportedPullClient), false,
            "write supportedPullClient failed");
    }
    return true;
}

DeviceInfo* DeviceInfo::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<DeviceInfo>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->ReadFromParcel(in), nullptr, "info is nullptr");
    return info.release();
}

bool DeviceInfo::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(castCategory_), false, "Read castCategory failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceId_), false, "Read deviceId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(deviceName_), false, "Read deviceName failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceType_), false, "Read deviceType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(ipAddress_), false, "Read ipAddress failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(networkId_), false, "Read networkId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(manufacturer_), false, "Read manufacturer failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(modelName_), false, "Read modelName failed");
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
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isLegacy_), false, "Read isLegacy failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(mediumTypes_), false, "Read mediumTypes failed");
    CHECK_AND_RETURN_RET_LOG(audioCapabilities_.ReadFromParcel(in), false, "Read audioCapability failed");

    int32_t supportedPullClientsLen = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(supportedPullClientsLen), false, "read supportedPullClientsLen failed");
    // max length of the clients vector
    int32_t maxSupportedPullClientsLen = 256;
    CHECK_AND_RETURN_RET_LOG((supportedPullClientsLen >= 0) &&
        (supportedPullClientsLen <= maxSupportedPullClientsLen), false, "supportedPullClientsLen is illegal");
    std::vector<uint32_t> supportedPullClients;
    for (int j = 0; j < supportedPullClientsLen; j++) {
        uint32_t supportedPullClient;
        CHECK_AND_RETURN_RET_LOG(in.ReadUint32(supportedPullClient), false,
            "read supportedPullClients failed");
        supportedPullClients.emplace_back(supportedPullClient);
    }
    supportedPullClients_ = supportedPullClients;
    return true;
}

bool OutputDeviceInfo::Marshalling(Parcel& out) const
{
    int32_t deviceInfoSize = static_cast<int32_t>(deviceInfos_.size());
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    for (DeviceInfo deviceInfo : deviceInfos_) {
        CHECK_AND_RETURN_RET_LOG(deviceInfo.Marshalling(out), false, "write deviceInfo failed");
    }
    return true;
}

OutputDeviceInfo* OutputDeviceInfo::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<OutputDeviceInfo>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->ReadFromParcel(in), nullptr, "info is nullptr");
    return info.release();
}

bool OutputDeviceInfo::ReadFromParcel(Parcel& in)
{
    int32_t deviceInfoSize = 0;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (int i = 0; i < deviceInfoSize; i++) {
        DeviceInfo deviceInfo;
        CHECK_AND_RETURN_RET_LOG(deviceInfo.ReadFromParcel(in), false, "read deviceInfo failed");
        deviceInfos_.emplace_back(deviceInfo);
    }
    return true;
}

bool AudioCapabilities::WriteToParcel(Parcel& out) const
{
    int32_t streamInfoSize = static_cast<int32_t>(streamInfos_.size());
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(streamInfoSize), false, "write streamInfoSize failed");
    for (AudioStreamInfo streamInfo : streamInfos_) {
        CHECK_AND_RETURN_RET_LOG(streamInfo.WriteToParcel(out), false, "write streamInfo failed");
    }
    return true;
}

bool AudioCapabilities::ReadFromParcel(Parcel& in)
{
    int32_t streamInfoSize;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(streamInfoSize), false, "read streamInfoSize failed");
    int32_t maxStreamInfoSize = 1000;
    CHECK_AND_RETURN_RET_LOG((streamInfoSize >= 0) && (streamInfoSize < maxStreamInfoSize),
        false, "streamInfoSize is illegal");
    for (int i = 0; i < streamInfoSize; i++) {
        AudioStreamInfo streamInfo {};
        CHECK_AND_RETURN_RET_LOG(streamInfo.ReadFromParcel(in), false, "read streamInfo failed");
        streamInfos_.emplace_back(streamInfo);
    }
    return true;
}

bool CastDisplayInfo::Marshalling(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(static_cast<int32_t>(displayState)), false, "write displayState failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteUint64(displayId), false, "write displayId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(name), false, "write name failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(width), false, "write width failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(height), false, "write height failed");
    return true;
}

CastDisplayInfo* CastDisplayInfo::Unmarshalling(Parcel& in)
{
    auto info = std::make_unique<CastDisplayInfo>();
    CHECK_AND_RETURN_RET_LOG(info != nullptr && info->ReadFromParcel(in), nullptr, "info is nullptr");
    return info.release();
}

bool CastDisplayInfo::ReadFromParcel(Parcel& in)
{
    int32_t displayStateTemp = -1;
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(displayStateTemp), false, "read displayState failed");
    if (displayStateTemp < static_cast<int32_t>(CastDisplayState::STATE_OFF) ||
        displayStateTemp > static_cast<int32_t>(CastDisplayState::STATE_ON)) {
        return false;
    }
    displayState = static_cast<CastDisplayState>(displayStateTemp);
    CHECK_AND_RETURN_RET_LOG(in.ReadUint64(displayId), false, "read displayId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(name), false, "read name failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(width), false, "read width failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(height), false, "read height failed");
    return true;
}
} // namespace OHOS::AVSession
