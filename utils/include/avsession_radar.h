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

#ifndef OHOS_AVSESSION_RADAR_H
#define OHOS_AVSESSION_RADAR_H

#include "radar_constants.h"
#include "element_name.h"
#include <string>
#include <algorithm>
#include "avsession_descriptor.h"
#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_host.h"
#include "iservice_registry.h"

namespace OHOS::AVSession {
struct AVSessionRadarInfo {
    int32_t bizScene_ { 0 };
    int32_t bizStage_ { 0 };
    int32_t stageRes_ { 0 };
    int32_t bizState_ { 0 };
    int32_t triggerMode_ { 0 };
    int32_t errorCode_ { 0 };
    int32_t isTrust_ { static_cast<int32_t>(TrustStatus::UNKOWN) };
    std::string hostPkg_;
    std::string toCallPkg_ { CAST_ENGINE_PKG };
    std::string func_;
    std::string discoveryDeviceList_;
    std::string peerUdid_;
    std::string peerBtMac_;
    std::string peerNetId_;
    std::string peerDevType_;
    std::string localSessName_;
    std::string peerSessName_;
    std::string bundleName_;
    std::string sourceType_;
    explicit AVSessionRadarInfo(std::string funcName) : func_(funcName) {}
    void CheckTriggerMode()
    {
        if (bundleName_.empty()) {
            triggerMode_ = static_cast<int32_t>(TriggerMode::UNKNOWN);
            return;
        }
        triggerMode_ = (bundleName_.find(MEDIA_CONTROL_PKG) == std::string::npos) ?
            static_cast<int32_t>(TriggerMode::APPLICATION) :
            static_cast<int32_t>(TriggerMode::MEDIA_CONTROL);
    }
};

class AVSessionRadar {
public:
    static AVSessionRadar &GetInstance();
    static std::string GetAnonymousDeviceId(std::string deviceId);
    static int32_t GetRadarErrorCode(int32_t err);
    void InitBMS();
    void GetJsonCastDeviceList(const OutputDeviceInfo &deviceInfo, std::string& deviceList);
    void GetPeerInfo(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info);
    void GetPeerInfoFromDeviceInfo(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info);

    void StartCastDiscoveryBegin(AVSessionRadarInfo &info);
    void StartCastDiscoveryEnd(AVSessionRadarInfo &info);
    void FailToStartCastDiscovery(AVSessionRadarInfo &info);

    void CastDeviceAvailable(const OutputDeviceInfo &castOutputDeviceInfo, AVSessionRadarInfo &info);

    void StopCastDiscoveryBegin(AVSessionRadarInfo &info);
    void StopCastDiscoveryEnd(AVSessionRadarInfo &info);
    void FailToStopCastDiscovery(AVSessionRadarInfo &info);

    void StartCastBegin(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info);
    void StartCastEnd(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info);
    void FailToStartCast(AVSessionRadarInfo &info);
    void FailToStartCast(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info);
    void StartConnect(AVSessionRadarInfo &info);
    void ConnectFinish(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info);

    void StartPlayBegin(AVSessionRadarInfo &info);
    void StartPlayEnd(AVSessionRadarInfo &info);
    void StartPlayFailed(AVSessionRadarInfo &info);
    void PlayerStarted(AVSessionRadarInfo &info);

    void SendControlCommandBegin(AVSessionRadarInfo &info);
    void SendControlCommandEnd(AVSessionRadarInfo &info);
    void FailToSendControlCommand(AVSessionRadarInfo &info);
    void ControlCommandRespond(AVSessionRadarInfo &info);
    void ControlCommandError(AVSessionRadarInfo &info);

    void StopCastBegin(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info);
    void StopCastEnd(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info);
    void StopCastFinish(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info);
    void FailToStopCast(AVSessionRadarInfo &info);
    void FailToStopCast(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info);

    void reset();

private:
    AVSessionRadar() = default;
    ~AVSessionRadar() = default;
    std::string GetLocalDeviceNetworkId();
    std::string GetUdidByNetworkId(const std::string &networkId);
    void ReportWithTrustInfo(AVSessionRadarInfo &info);
    void ReportWithoutTrustInfo(AVSessionRadarInfo &info);
    void ReportHiSysEventBehavior(AVSessionRadarInfo &info);
    std::string ConvertHexToString(int32_t hex);
    std::string GetLocalDevType();
    std::string GetBundleNameFromUid(int32_t uid);

private:
    std::string orgPkg_ { AVSESSION_PKG_NAME };
    std::string localUdid_;
    std::string localNetId_;
    std::string localDevType_;
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_RADAR_H