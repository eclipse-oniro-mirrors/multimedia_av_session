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

#ifndef OHOS_AVSESSION_DESCRIPTOR_H
#define OHOS_AVSESSION_DESCRIPTOR_H

#include "parcel.h"
#include "element_name.h"

namespace OHOS::AVSession {
struct DeviceInfo {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel& in);

    int32_t castCategory_;
    std::string deviceId_;
    std::string deviceName_;
    std::string networkId_;
    std::string ipAddress_;
    int32_t deviceType_;
    int32_t providerId_;
    int32_t supportedProtocols_ = 3;
    int32_t authenticationStatus_ = 0;
    std::vector<std::string> supportedDrmCapabilities_;
};

struct OutputDeviceInfo {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel& in);

    std::vector<DeviceInfo> deviceInfos_;
};

struct AVHistoryDescriptor {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel& in);

    std::string sessionId_;
    std::string bundleName_;
    std::string abilityName_;
};

struct AVSessionDescriptor {
    bool WriteToParcel(Parcel& out) const;
    bool CheckBeforReadFromParcel(Parcel& in);
    bool CheckBeforReadFromParcel(Parcel& in, DeviceInfo& deviceInfo);
    bool ReadFromParcel(Parcel& in);

    std::string sessionId_;
    int32_t sessionType_ {};
    std::string sessionTag_;
    AppExecFwk::ElementName elementName_;
    pid_t pid_ {};
    pid_t uid_ {};
    bool isActive_ {};
    bool isTopSession_ {};
    bool isThirdPartyApp_ {};
    OutputDeviceInfo outputDeviceInfo_;
};

struct AVSessionBasicInfo {
    std::string deviceName_;
    std::string networkId_;
    std::string vendorId_;
    std::string deviceType_;
    std::string systemVersion_;
    int32_t sessionVersion_ {};
    std::vector<int32_t> reserve_;
    std::vector<int32_t> feature_;
    std::vector<int32_t> metaDataCap_;
    std::vector<int32_t> playBackStateCap_;
    std::vector<int32_t> controlCommandCap_;
    std::vector<int32_t> extendCapability_;
    int32_t systemTime_ {};
    std::vector<int32_t> extend_;
};

enum CastDisplayState {
    STATE_OFF = 1,
    STATE_ON,
};

struct CastDisplayInfo {
    CastDisplayState displayState;
    uint64_t displayId;
    std::string name;
    int32_t width;
    int32_t height;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DESCRIPTOR_H