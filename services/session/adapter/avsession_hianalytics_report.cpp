/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include <unordered_map>

#include "avsession_hianalytics_report.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "device_manager.h"
#include "dm_device_info.h"


namespace OHOS::AVSession {
const int32_t CAST_CONNECT_STATE = 6;
const int32_t CAST_STREAM = 2;
const int32_t DLNA = 4;
const int32_t CAST_AND_STREAM = 6;
const int32_t CONNECT = 1;
const int32_t DISCONNECT = 2;
const char *HA_INSTANCE_TAG = "$SceneDataShare";
const char *HA_AVCAST_RECOMMEND_ID = "$APP_AVCAST_RECOMMEND";
const char *HA_AVCAST_EVENT_ID = "$APP_AVCAST_EVENT";
const char *HA_AVCAST_RECORD_ID = "$APP_AVCAST_RECORD";
const char *HA_KEY_AVCAST_STATE = "$Status";
const char *HA_KEY_PROTOCOL_TYPE = "$ProtocolType";
const char *HA_KEY_SRC_BUNDLE_NAME = "$BundleName";
const char *HA_KEY_SRC_NETWORK_ID = "$SrcNetworkId";
const char *HA_KEY_SRC_DEVICE_ID = "$SrcDeviceId";
const char *HA_KEY_SRC_DEVICE_TYPE = "$SrcDeviceType";
const char *HA_KEY_SRC_DEVICE_NAME = "$SrcDeviceName";
const char *HA_KEY_PEER_NETWORK_ID = "$PeerNetworkId";
const char *HA_KEY_PEER_DEVICE_ID = "$PeerDeviceId";
const char *HA_KEY_PEER_DEVICE_TYPE = "$PeerDeviceType";
const char *HA_KEY_PEER_DEVICE_NAME = "$PeerDeviceName";
const char *HA_KEY_AVSESSION_ID = "$SessionId";
const char *HA_KEY_AVSESSION_MEDIA_ID = "$MediaId";
const char *HA_KEY_AVSESSION_TYPE = "$SessionType";
const char *HA_KEY_RESOURCE_DURATION = "$Duration";

std::string GetProtocol(int supportProtocol)
{
    switch (supportProtocol) {
        case CAST_STREAM:
        case CAST_AND_STREAM:
            return "CastStream";
        case DLNA:
            return "DLNA";
        default:
            return "LOCAL";
    }
}

void AVSessionHiAnalyticsReport::ConnectHAClient(std::string eventId,
    std::unordered_map<std::string, std::string> properties)
{
    SLOGI("ConnectHAClient start");
    void *haClientHandle = dlopen("libha_client_core.z.so", RTLD_NOW);
    CHECK_AND_RETURN_LOG(haClientHandle != nullptr, "dlopen ha_client failed, reason:%{public}sn", dlerror());
    // get release func
    void *releaseFunc = dlsym(haClientHandle, "release");
    if (releaseFunc == nullptr) {
        SLOGE("dlsm release func failed, reason:%{public}sn", dlerror());
        dlclose(haClientHandle);
        return;
    }
    void *onHAEventFunc = dlsym(haClientHandle, "onEvent");
    if (onHAEventFunc == nullptr) {
        SLOGE("dlsm onEvent failed, reason:%{public}sn", dlerror());
        dlclose(haClientHandle);
        return;
    }
    auto onHAEvent = reinterpret_cast<HaResponseLite(*)(
        std::string, int32_t, std::string, std::unordered_map<std::string, std::string>)>(onHAEventFunc);
    onHAEvent(HA_INSTANCE_TAG, 0, eventId, properties);
    SLOGI("OnHaEvent eventId: %{public}s", eventId.c_str());
    auto haRelease = reinterpret_cast<HaResponseLite(*)()>(releaseFunc);
    haRelease();
    dlclose(haClientHandle);
}

void AVSessionHiAnalyticsReport::PublishRecommendInfo(const std::string &bundleName, const std::string &sessionId,
    const std::string &sessionType, const std::string &assetId, const int32_t duration)
{
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_SRC_BUNDLE_NAME, bundleName);
    properties.emplace(HA_KEY_AVSESSION_ID, sessionId);
    properties.emplace(HA_KEY_AVSESSION_TYPE, sessionType);
    properties.emplace(HA_KEY_AVSESSION_MEDIA_ID, assetId);
    properties.emplace(HA_KEY_RESOURCE_DURATION, std::to_string(duration));
    SLOGI("PublishRecommendInfo: bundleName:%{public}s duration:%{public}d", bundleName.c_str(), duration);
    ConnectHAClient(HA_AVCAST_RECOMMEND_ID, properties);
    return;
}

void AVSessionHiAnalyticsReport::PublishCastEvent(const std::string &bundleName, const int32_t castState,
    const DeviceInfo deviceInfo)
{
    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo("av_session", dmDeviceInfo);
    CHECK_AND_RETURN_LOG(ret == 0, "get local deviceInfo failed");
    std::string localNetworkId = dmDeviceInfo.networkId;
    std::string localDeviceId = dmDeviceInfo.deviceId;
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_SRC_BUNDLE_NAME, bundleName);
    properties.emplace(HA_KEY_AVCAST_STATE, std::to_string(castState == CAST_CONNECT_STATE ? CONNECT : DISCONNECT));
    properties.emplace(HA_KEY_SRC_DEVICE_ID, localDeviceId);
    properties.emplace(HA_KEY_SRC_NETWORK_ID, localNetworkId);
    properties.emplace(HA_KEY_PEER_DEVICE_ID, deviceInfo.deviceId_);
    properties.emplace(HA_KEY_PEER_NETWORK_ID, deviceInfo.networkId_);
    SLOGI("PublishCastEvent: bundleName:%{public}s castState:%{public}d", bundleName.c_str(), castState);
    ConnectHAClient(HA_AVCAST_EVENT_ID, properties);
    return;
}

void AVSessionHiAnalyticsReport::PublishCastRecord(const std::string &bundleName, const DeviceInfo deviceInfo)
{
    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo("av_session", dmDeviceInfo);
    CHECK_AND_RETURN_LOG(ret == 0, "get local deviceInfo failed");
    std::string localNetworkId = dmDeviceInfo.networkId;
    std::string localDeviceId = dmDeviceInfo.deviceId;
    uint16_t localDeviceType = dmDeviceInfo.deviceTypeId;
    std::string localDeviceName = dmDeviceInfo.deviceName;
    std::unordered_map<std::string, std::string> properties;
    properties.emplace(HA_KEY_SRC_BUNDLE_NAME, bundleName);
    properties.emplace(HA_KEY_PROTOCOL_TYPE, GetProtocol(deviceInfo.supportedProtocols_));
    properties.emplace(HA_KEY_SRC_DEVICE_ID, localDeviceId);
    properties.emplace(HA_KEY_SRC_NETWORK_ID, localNetworkId);
    properties.emplace(HA_KEY_SRC_DEVICE_TYPE, std::to_string(localDeviceType));
    properties.emplace(HA_KEY_SRC_DEVICE_NAME, localDeviceName);
    properties.emplace(HA_KEY_PEER_DEVICE_ID, deviceInfo.deviceId_);
    properties.emplace(HA_KEY_PEER_NETWORK_ID, deviceInfo.networkId_);
    properties.emplace(HA_KEY_PEER_DEVICE_TYPE, std::to_string(deviceInfo.deviceType_));
    properties.emplace(HA_KEY_PEER_DEVICE_NAME, deviceInfo.deviceName_);
    SLOGI("PublishCastRecord: bundleName:%{public}s Protocol:%{public}d srcDevice:%{public}s peerDevice:%{public}s",
        bundleName.c_str(), deviceInfo.supportedProtocols_, localDeviceName.c_str(), deviceInfo.deviceName_.c_str());
    ConnectHAClient(HA_AVCAST_RECORD_ID, properties);
    return;
}
}
