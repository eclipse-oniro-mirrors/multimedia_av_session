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

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include "avsession_radar.h"
#include "device_manager.h"
#include "radar_constants.h"
#include "avsession_log.h"
#include "avsession_sysevent.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "cJSON.h"

namespace OHOS::AVSession {
AVSessionRadar& AVSessionRadar::GetInstance()
{
    static AVSessionRadar avSessionRadar;
    return avSessionRadar;
}

// LCOV_EXCL_START
std::string AVSessionRadar::GetAnonymousDeviceId(std::string deviceId)
{
    const uint32_t half = DEVICE_ID_MIN_LEN / 2;
    if (deviceId.empty() || deviceId.length() < DEVICE_ID_MIN_LEN) {
        return "unknown";
    }
    return deviceId.substr(0, half) + "**" + deviceId.substr(deviceId.length() - half);
}

int32_t AVSessionRadar::GetRadarErrorCode(int32_t err)
{
    constexpr int32_t systemShift = 21;
    constexpr int32_t moduleShift = 16;
    uint32_t errorCode =
        (AV_SESSION_SYSTEM_ID << systemShift) | (AV_SESSION_MODULE_ID << moduleShift) |
        (static_cast<uint>(abs(err)) & 0xFFFF);
    SLOGI("GetRadarErrorCode err:%{public}d -> %{public}d", abs(err), errorCode);
    return errorCode;
}

std::string AVSessionRadar::GetLocalDeviceNetworkId()
{
    std::string networkId = "";
    if (OHOS::DistributedHardware::DeviceManager::GetInstance()
        .GetLocalDeviceNetWorkId(AVSESSION_PKG_NAME, networkId) != 0) {
        SLOGE("GetLocalDeviceNetWorkId failed");
    }

    return networkId;
}

std::string AVSessionRadar::GetUdidByNetworkId(const std::string &networkId)
{
    std::string localDevUdid = "";
    if (OHOS::DistributedHardware::DeviceManager::GetInstance()
        .GetUdidByNetworkId(AVSESSION_PKG_NAME, networkId, localDevUdid) != 0) {
        SLOGE("GetUdidByNetworkId failed");
    }
    return localDevUdid;
}

std::string AVSessionRadar::ConvertHexToString(int32_t hex)
{
    std::stringstream str;
    int32_t width = 3;
    str << std::hex << std::setw(width) << std::setfill('0') << hex;
    std::string hexStr = str.str();
    transform(hexStr.begin(), hexStr.end(), hexStr.begin(), ::toupper);
    return hexStr;
}
// LCOV_EXCL_STOP

std::string AVSessionRadar::GetLocalDevType()
{
    SLOGI("GetLocalDevType");
    int32_t localDevType = 0;
    if (OHOS::DistributedHardware::DeviceManager::GetInstance()
        .GetLocalDeviceType(AVSESSION_PKG_NAME, localDevType) != 0) {
        SLOGE("GetLocalDevType failed");
    } else {
        SLOGI("GetLocalDevType: %{public}d", localDevType);
    }
    return ConvertHexToString(localDevType);
}

void AVSessionRadar::reset()
{
    localNetId_.clear();
    localUdid_.clear();
    localDevType_.clear();
}

void AVSessionRadar::InitBMS()
{
    SLOGI("InitBMS");
        auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        SLOGE("fail to get system ability mgr");
        return;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        SLOGE("fail to get bundle manager proxy");
        return;
    }

    SLOGI("get bundle manager proxy success");
    bundleMgrProxy_ = iface_cast<AppExecFwk::BundleMgrProxy>(remoteObject);
}

// LCOV_EXCL_START
void AVSessionRadar::GetJsonCastDeviceList(const OutputDeviceInfo &deviceInfo, std::string& deviceList)
{
    cJSON* jDeviceInfos = cJSON_CreateArray();
    for (const DeviceInfo& deviceInfo : deviceInfo.deviceInfos_) {
        cJSON* jDeviceInfo = cJSON_CreateObject();
        if (jDeviceInfo == nullptr) {
            SLOGE("fail create jDeviceInfo");
            continue;
        }
        if (cJSON_IsInvalid(jDeviceInfo) || cJSON_IsNull(jDeviceInfo)) {
            SLOGE("create jDeviceInfo invalid");
            cJSON_Delete(jDeviceInfo);
            continue;
        }
        cJSON_AddStringToObject(jDeviceInfo, PEER_UDID,
            GetAnonymousDeviceId(GetUdidByNetworkId(deviceInfo.networkId_)).c_str());
        cJSON_AddStringToObject(jDeviceInfo, PEER_BT_MAC, "");
        cJSON_AddStringToObject(jDeviceInfo, PEER_DEV_TYPE, ConvertHexToString(deviceInfo.deviceType_).c_str());
        cJSON_AddStringToObject(jDeviceInfo, PEER_DEV_NAME, deviceInfo.deviceName_.c_str());
        cJSON_AddItemToArray(jDeviceInfos, jDeviceInfo);
    }

    char* jDeviceInfosStr = cJSON_Print(jDeviceInfos);
    if (jDeviceInfosStr != nullptr) {
        deviceList = jDeviceInfosStr;
        cJSON_free(jDeviceInfosStr);
    } else {
        SLOGE("get jDeviceInfosStr with nullptr");
    }
    cJSON_Delete(jDeviceInfos);
}

void AVSessionRadar::GetPeerInfoFromDeviceInfo(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info)
{
    info.peerUdid_ = GetAnonymousDeviceId(GetUdidByNetworkId(deviceInfo.networkId_));
    info.peerBtMac_ = "";
    info.peerNetId_ = GetAnonymousDeviceId(deviceInfo.networkId_);
    info.peerDevType_ = ConvertHexToString(deviceInfo.deviceType_);
    info.isTrust_ = (deviceInfo.authenticationStatus_ == 0) ?
        static_cast<int32_t>(TrustStatus::UNTRUST) : static_cast<int32_t>(TrustStatus::TRUST);
}

std::string AVSessionRadar::GetBundleNameFromUid(int32_t uid)
{
    std::string bundleName{""};
    if (bundleMgrProxy_ != nullptr) {
        bundleMgrProxy_->GetNameForUid(uid, bundleName);
        SLOGI("get bundleName:%{public}s uid:%{public}d", bundleName.c_str(), uid);
    } else {
        SLOGE("can't get bundleName for uid:%{public}d", uid);
    }
    return bundleName;
}

void AVSessionRadar::GetPeerInfo(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info)
{
    if (outputDeviceInfo.deviceInfos_.size() > 0) {
        GetPeerInfoFromDeviceInfo(outputDeviceInfo.deviceInfos_[0], info);
    }
}

void AVSessionRadar::ReportWithoutTrustInfo(AVSessionRadarInfo &info)
{
    HISYSEVENT_BEHAVIOR(AVSESSION_CAST_BEHAVIOR,
        ORG_PKG, orgPkg_,
        HOST_PKG, info.hostPkg_,
        TO_CALL_PKG, info.toCallPkg_,
        TRIGGER_MODE, info.triggerMode_,
        FUNC, info.func_,
        BIZ_SCENE, info.bizScene_,
        BIZ_STAGE, info.bizStage_,
        STAGE_RES, info.stageRes_,
        BIZ_STATE, info.bizState_,
        ERROR_CODE, info.errorCode_,
        DISCOVERY_DEVICE_LIST, info.discoveryDeviceList_,
        LOCAL_UDID, localUdid_,
        LOCAL_NET_ID, localNetId_,
        LOCAL_DEV_TYPE, localDevType_,
        PEER_UDID, info.peerUdid_,
        PEER_BT_MAC, info.peerBtMac_,
        PEER_NET_ID, info.peerNetId_,
        PEER_DEV_TYPE, info.peerDevType_,
        SOURCE_TYPE, info.sourceType_);
}

void AVSessionRadar::ReportWithTrustInfo(AVSessionRadarInfo &info)
{
    HISYSEVENT_BEHAVIOR(AVSESSION_CAST_BEHAVIOR,
        ORG_PKG, orgPkg_,
        HOST_PKG, info.hostPkg_,
        TO_CALL_PKG, info.toCallPkg_,
        TRIGGER_MODE, info.triggerMode_,
        FUNC, info.func_,
        BIZ_SCENE, info.bizScene_,
        BIZ_STAGE, info.bizStage_,
        STAGE_RES, info.stageRes_,
        BIZ_STATE, info.bizState_,
        ERROR_CODE, info.errorCode_,
        DISCOVERY_DEVICE_LIST, info.discoveryDeviceList_,
        LOCAL_UDID, localUdid_,
        LOCAL_NET_ID, localNetId_,
        LOCAL_DEV_TYPE, localDevType_,
        PEER_UDID, info.peerUdid_,
        PEER_BT_MAC, info.peerBtMac_,
        PEER_NET_ID, info.peerNetId_,
        PEER_DEV_TYPE, info.peerDevType_,
        SOURCE_TYPE, info.sourceType_,
        IS_TRUST, info.isTrust_);
}

void AVSessionRadar::ReportHiSysEventBehavior(AVSessionRadarInfo &info)
{
    if (localNetId_.empty()) {
        localNetId_ = GetAnonymousDeviceId(GetLocalDeviceNetworkId());
    }
    if (localUdid_.empty()) {
        localUdid_ = GetAnonymousDeviceId(GetUdidByNetworkId(GetLocalDeviceNetworkId()));
    }
    if (localDevType_.empty()) {
        localDevType_ = GetLocalDevType();
    }
    if (info.bundleName_.empty()) {
        int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
        SLOGI("%{public}s func:%{public}s callingUid:%{public}d", __FUNCTION__, info.func_.c_str(), uid);
        info.bundleName_ = GetBundleNameFromUid(uid);
    }
    info.CheckTriggerMode();
    if (!info.bundleName_.empty()) {
        info.hostPkg_ =
            (info.bundleName_.find(MEDIA_CONTROL_PKG) != std::string::npos) ? MEDIA_CONTROL_PKG : info.bundleName_;
    }
    if (info.errorCode_ == 0) {
        info.errorCode_ = GetRadarErrorCode(0);
    }
    if (info.isTrust_ == static_cast<int32_t>(TrustStatus::UNKOWN)) {
        ReportWithoutTrustInfo(info);
    } else {
        ReportWithTrustInfo(info);
    }
}

void AVSessionRadar::StartCastDiscoveryBegin(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartCastDiscoveryEnd(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToStartCastDiscovery(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::CastDeviceAvailable(const OutputDeviceInfo &castOutputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::DISPLAY);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);

    GetJsonCastDeviceList(castOutputDeviceInfo, info.discoveryDeviceList_);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StopCastDiscoveryBegin(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::STOP);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StopCastDiscoveryEnd(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::STOP);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToStopCastDiscovery(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_DISCOVERY);
    info.bizStage_ = static_cast<int32_t>(CastDiscoveryStage::STOP);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartCastBegin(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}
// LCOV_EXCL_STOP

void AVSessionRadar::StartCastEnd(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}

// LCOV_EXCL_START
void AVSessionRadar::FailToStartCast(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToStartCast(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::START);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartConnect(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::CONNECT);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::ConnectFinish(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::CONNECT);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfoFromDeviceInfo(deviceInfo, info);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartPlayBegin(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::STARTED);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartPlayEnd(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::STARTED);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StartPlayFailed(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::STARTED);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::PlayerStarted(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_START);
    info.bizStage_ = static_cast<int32_t>(CastStartStage::STARTED);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::SendControlCommandBegin(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_CONTROL);
    info.bizStage_ = static_cast<int32_t>(CastControlStage::SEND_COMMAND);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::SendControlCommandEnd(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_CONTROL);
    info.bizStage_ = static_cast<int32_t>(CastControlStage::SEND_COMMAND);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToSendControlCommand(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_CONTROL);
    info.bizStage_ = static_cast<int32_t>(CastControlStage::SEND_COMMAND);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::ControlCommandRespond(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_CONTROL);
    info.bizStage_ = static_cast<int32_t>(CastControlStage::RECV_COMMAND);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::ControlCommandError(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_CONTROL);
    info.bizStage_ = static_cast<int32_t>(CastControlStage::RECV_COMMAND);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StopCastBegin(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_END);
    info.bizStage_ = static_cast<int32_t>(CastStopStage::STOP_BEGIN);
    info.stageRes_ = static_cast<int32_t>(StageResult::IDLE);
    info.bizState_ = static_cast<int32_t>(BizState::BEGIN);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StopCastEnd(const OutputDeviceInfo& outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_END);
    info.bizStage_ = static_cast<int32_t>(CastStopStage::STOP_BEGIN);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToStopCast(AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_END);
    info.bizStage_ = static_cast<int32_t>(CastStopStage::STOP_BEGIN);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::FailToStopCast(const OutputDeviceInfo &outputDeviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_END);
    info.bizStage_ = static_cast<int32_t>(CastStopStage::STOP_BEGIN);
    info.stageRes_ = static_cast<int32_t>(StageResult::FAIL);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfo(outputDeviceInfo, info);
    ReportHiSysEventBehavior(info);
}

void AVSessionRadar::StopCastFinish(const DeviceInfo &deviceInfo, AVSessionRadarInfo &info)
{
    info.bizScene_ = static_cast<int32_t>(BizScene::CAST_END);
    info.bizStage_ = static_cast<int32_t>(CastStopStage::STOP_END);
    info.stageRes_ = static_cast<int32_t>(StageResult::SUCCESS);
    info.bizState_ = static_cast<int32_t>(BizState::END);
    GetPeerInfoFromDeviceInfo(deviceInfo, info);
    ReportHiSysEventBehavior(info);
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
