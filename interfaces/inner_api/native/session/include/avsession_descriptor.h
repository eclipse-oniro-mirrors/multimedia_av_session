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

#ifndef OHOS_AVSESSION_DESCRIPTOR_H
#define OHOS_AVSESSION_DESCRIPTOR_H

#include "parcel.h"
#include "element_name.h"
#include "av_audio_stream_info.h"

namespace OHOS::AVSession {
struct AudioCapabilities {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel& in);

    std::vector<AudioStreamInfo> streamInfos_;
};

class DeviceInfo : public Parcelable {
public:
    DeviceInfo() = default;
    DeviceInfo(int32_t castCategory, std::string deviceId, std::string deviceName)
        : castCategory_(castCategory), deviceId_(deviceId), deviceName_(deviceName) {}
    bool Marshalling(Parcel& out) const override;
    bool ReadFromParcel(Parcel& in);
    static DeviceInfo* Unmarshalling(Parcel& in);

    int32_t castCategory_ {};
    std::string deviceId_;
    std::string deviceName_;
    std::string networkId_;
    std::string ipAddress_;
    std::string manufacturer_;
    std::string modelName_;
    int32_t deviceType_ {};
    int32_t providerId_ {};
    int32_t supportedProtocols_ {};
    int32_t authenticationStatus_ {};
    std::vector<std::string> supportedDrmCapabilities_;
    bool isLegacy_ = false;
    int32_t mediumTypes_ = 2;
    AudioCapabilities audioCapabilities_;
};

class OutputDeviceInfo : public Parcelable {
public:
    bool Marshalling(Parcel& out) const override;
    bool ReadFromParcel(Parcel& in);
    static OutputDeviceInfo* Unmarshalling(Parcel& in);

    std::vector<DeviceInfo> deviceInfos_;
};

class AVHistoryDescriptor : public Parcelable {
    bool Marshalling(Parcel& out) const override;
    bool ReadFromParcel(Parcel& in);
    static AVHistoryDescriptor* Unmarshalling(Parcel& in);

    std::string sessionId_;
    std::string bundleName_;
    std::string abilityName_;
};

class AVSessionDescriptor : public Parcelable {
public:
    bool Marshalling(Parcel& out) const override;
    bool CheckBeforReadFromParcel(Parcel& in);
    bool CheckBeforReadFromParcel(Parcel& in, DeviceInfo& deviceInfo);
    bool ReadFromParcel(Parcel& in);
    static AVSessionDescriptor* Unmarshalling(Parcel& in);

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

    int32_t userId_ {};
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

enum DeviceLogEventCode {
    DEVICE_LOG_FULL = 1,
    DEVICE_LOG_EXCEPTION = 2,
    DEVICE_LOG_MAX = 3,
};

struct CastDisplayInfo: public Parcelable {
    bool Marshalling(Parcel& out) const override;
    bool ReadFromParcel(Parcel& in);
    static CastDisplayInfo* Unmarshalling(Parcel& in);

    CastDisplayState displayState;
    uint64_t displayId {};
    std::string name;
    int32_t width {};
    int32_t height {};
};

enum ReasonCode {
    REASON_DEFAULT = 0,
    REASON_TRUST_BY_SINK = 10000,
    REASON_CANCEL_BY_SOURCE = 10001,
    REASON_BIND_COMPLETE = 10002,
    REASON_SHOW_TRUST_SELECT_UI = 10003,
    REASON_STOP_BIND_BY_SOURCE = 10004,
    REASON_PIN_CODE_OVER_RETRY = 10005,
    REASON_CANCEL_BY_SINK = 10006,
    REASON_DISTRUST_BY_SINK = 10007,
    REASON_CONNECTION_TIMEOUT = 10008,
    REASON_DEVICE_IS_BUSY = 10009,
    REASON_SCREEN_NOT_EXIST = 10010,
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DESCRIPTOR_H