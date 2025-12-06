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

#include "hw_cast_provider.h"
#include <thread>
#include "cast_session_manager.h"
#include "hw_cast_stream_player.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_event_handler.h"
#include "avsession_radar.h"

using namespace OHOS::CastEngine::CastEngineClient;
using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
const uint32_t UNTRUSTED_DEVICE = 0;
const uint32_t TRUSTED_DEVICE = 1;

HwCastProvider::HwCastProvider()
{
    SLOGD("pre construct the HwCastProvider");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("construct the HwCastProvider");
}

HwCastProvider::~HwCastProvider()
{
    SLOGD("pre destruct the HwCastProvider");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("destruct the HwCastProvider");
}

int32_t HwCastProvider::Init()
{
    SLOGD("pre init the HwCastProvider");
    std::lock_guard lockGuard(mutexLock_);
    int32_t ret = CastSessionManager::GetInstance().RegisterListener(shared_from_this());
    SLOGI("Init the HwCastProvider %{public}d", ret);
    return ret;
}

int32_t HwCastProvider::StartDeviceLogging(int32_t fd, uint32_t maxSize)
{
    SLOGI("start StartDeviceLogging, fd is %{public}d and maxSize is %{public}d", fd, maxSize);
    return CastSessionManager::GetInstance().StartDeviceLogging(fd, maxSize);
}

int32_t HwCastProvider::StopDeviceLogging()
{
    SLOGI("StopDeviceLogging");
    return CastSessionManager::GetInstance().StartDeviceLogging(-1, 0);
}

bool HwCastProvider::StartDiscovery(int castCapability, std::vector<std::string> drmSchemes)
{
    SLOGI("start discovery and the castCapability is %{public}d", castCapability);
    castCapability = GetCastProtocolType(castCapability);
    AVSessionRadarInfo info("HwCastProvider::StartDiscovery");
    AVSessionRadar::GetInstance().StartCastDiscoveryBegin(info);
    auto ret = CastSessionManager::GetInstance().StartDiscovery(castCapability, drmSchemes);
    if (ret != 0) {
        info.errorCode_ = ret;
        AVSessionRadar::GetInstance().FailToStartCastDiscovery(info);
    } else {
        AVSessionRadar::GetInstance().StartCastDiscoveryEnd(info);
    }
    return ret;
}

void HwCastProvider::StopDiscovery()
{
    SLOGI("stop discovery");
    AVSessionRadarInfo info("HwCastProvider::StopDiscovery");
    AVSessionRadar::GetInstance().StopCastDiscoveryBegin(info);
    auto ret = CastSessionManager::GetInstance().StopDiscovery();
    if (ret != 0) {
        info.errorCode_ = ret;
        AVSessionRadar::GetInstance().FailToStopCastDiscovery(info);
    } else {
        AVSessionRadar::GetInstance().StopCastDiscoveryEnd(info);
    }
}

int32_t HwCastProvider::SetDiscoverable(const bool enable)
{
    SLOGI("SetDiscoverable in %{public}d", static_cast<int32_t>(enable));
    return AVSESSION_SUCCESS;
}

void HwCastProvider::Release()
{
    SLOGI("cast provider release");
    {
        std::lock_guard lockGuard(mutexLock_);
        hwCastProviderSessionMap_.clear();
        avCastControllerMap_.clear();
        castStateListenerList_.clear();
        castFlag_.clear();
    }
    if (!isRelease_) {
        SLOGI("release in with check pass");
        isRelease_ = true;
    } else {
        SLOGW("already in release, check return");
        return;
    }
    CastSessionManager::GetInstance().UnregisterListener();
    SLOGD("provider release done");
}

int HwCastProvider::StartCastSession(bool isHiStream)
{
    SLOGI("StartCastSession begin");
    CastSessionProperty property = {
        isHiStream ? CastEngine::ProtocolType::CAST_PLUS_AUDIO : CastEngine::ProtocolType::CAST_PLUS_STREAM,
        CastEngine::EndType::CAST_SOURCE};
    std::shared_ptr<ICastSession> castSession = nullptr;
    int ret = CastSessionManager::GetInstance().CreateCastSession(property, castSession);
    if (ret != AVSESSION_SUCCESS) {
        AVSessionRadarInfo info("HwCastProvider::StartCastSession");
        info.errorCode_ = ret;
        AVSessionRadar::GetInstance().FailToStartCast(info);
        SLOGI("StartCastSession failed and return the ret is %{public}d", ret);
        return AVSESSION_ERROR;
    }
    int castId;
    {
        SLOGI("StartCastSession pre check lock");
        std::lock_guard lockGuard(mutexLock_);
        SLOGI("StartCastSession check lock");
        std::vector<bool>::iterator iter = find(castFlag_.begin(), castFlag_.end(), false);
        if (iter == castFlag_.end()) {
            SLOGE("StartCastSession failed");
            return AVSESSION_ERROR;
        }
        *iter = true;
        castId = iter - castFlag_.begin();
        auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
        if (hwCastProviderSession) {
            if (hwCastProviderSession->Init() != AVSESSION_ERROR) {
                hwCastProviderSession->SetCastSource(true);
                SLOGI("CastSession init successed");
            } else {
                hwCastProviderSession->Release();
                return AVSESSION_ERROR;
            }
            if (isHiStream) {
                hwCastProviderSession->SetProtocolType(CastEngine::ProtocolType::CAST_PLUS_AUDIO);
            }
        }
        hwCastProviderSessionMap_[castId] = hwCastProviderSession;
    }
    SLOGI("StartCastSession successed and return the castId is %{public}d", castId);

    return castId;
}
void HwCastProvider::StopCastSession(int castId)
{
    SLOGI("StopCastSession begin");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("StopCastSession check lock");
    auto hwCastStreamPlayer = avCastControllerMap_[castId];
    if (hwCastStreamPlayer) {
        hwCastStreamPlayer->Release();
    }
    avCastControllerMap_.erase(castId);
    int32_t mirrorCastId = static_cast<int32_t>((static_cast<uint64_t>(mirrorCastHandle) << 32) >> 32);
    if (castId == mirrorCastId) {
        return;
    }
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("no need to release castSession for castId %{public}d is not exit in hwCastProviderSessionMap_", castId);
        return;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession) {
        hwCastProviderSession->Release();
    }
    hwCastProviderSessionMap_.erase(castId);
    castFlag_[castId] = false;
}

bool HwCastProvider::AddCastDevice(int castId, DeviceInfo deviceInfo, uint32_t spid)
{
    SLOGI("AddCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("add device check lock done");

    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("the castId corresonding to castSession is not exist");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (!hwCastProviderSession) {
        SLOGE("the castId corresonding to castSession is nullptr");
        return false;
    }

    return hwCastProviderSession->AddDevice(deviceInfo, spid);
}

bool HwCastProvider::RemoveCastDevice(int castId, DeviceInfo deviceInfo, bool continuePlay)
{
    SLOGI("RemoveCastDevice with config castSession and corresonding castId is %{public}d", castId);
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("remove device check lock");
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("the castId corresonding to castSession is not exist");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (!hwCastProviderSession) {
        SLOGE("the castId corresonding to castSession is nullptr");
        return false;
    }

    return hwCastProviderSession->RemoveDevice(deviceInfo.deviceId_, continuePlay);
}

bool HwCastProvider::RegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener)
{
    SLOGI("RegisterCastStateListener in");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("RegisterCastStateListener in pass lock");
    if (listener == nullptr) {
        SLOGE("RegisterCastStateListener the listener is nullptr");
        return false;
    }
    if (find(castStateListenerList_.begin(), castStateListenerList_.end(), listener) != castStateListenerList_.end()) {
        SLOGE("RegisterCastStateListener the listener is already be registered");
        return false;
    }
    SLOGI("RegisterCastStateListener successed, and save it in the castStateListenerList_");
    castStateListenerList_.emplace_back(listener);

    return true;
}

bool HwCastProvider::UnRegisterCastStateListener(std::shared_ptr<IAVCastStateListener> listener)
{
    SLOGI("UnRegisterCastStateListener in");
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("UnRegisterCastStateListener in pass lock");
    if (listener == nullptr) {
        SLOGE("UnRegisterCastStateListener the listener is nullptr");
        return false;
    }
    for (auto iter = castStateListenerList_.begin(); iter != castStateListenerList_.end();) {
        if (*iter == listener) {
            castStateListenerList_.erase(iter);
            SLOGI("UnRegisterCastStateListener successed, and erase it from castStateListenerList_");
            return true;
        } else {
            ++iter;
        }
    }
    SLOGE("listener is not found in castStateListenerList_, so UnRegisterCastStateListener failed");

    return false;
}

std::shared_ptr<IAVCastControllerProxy> HwCastProvider::GetRemoteController(int castId)
{
    SLOGI("get remote controller with castId %{public}d", static_cast<int32_t>(castId));
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("get remote controller check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (avCastControllerMap_.find(castId) != avCastControllerMap_.end()) {
        SLOGI("the castId corresonding to streamPlayer is already exist");
        return avCastControllerMap_[castId];
    }
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("No castSession corresonding to castId exists");
        return nullptr;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("castSession corresonding to castId is nullptr");
        return nullptr;
    }
    std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
    std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = std::make_shared<HwCastStreamPlayer>(streamPlayer);
    if (!hwCastStreamPlayer) {
        SLOGE("the created hwCastStreamPlayer is nullptr");
        return nullptr;
    }
    if (hwCastStreamPlayer->Init() == AVSESSION_ERROR) {
        SLOGE("hwCastStreamPlayer init failed");
        return nullptr;
    }
    avCastControllerMap_[castId] = hwCastStreamPlayer;
    SLOGI("Create streamPlayer finished");
    return hwCastStreamPlayer;
}

bool HwCastProvider::SetStreamState(int64_t castHandle, DeviceInfo deviceInfo)
{
    int32_t castId = static_cast<int32_t>((static_cast<uint64_t>(castHandle) << 32) >> 32);
    mirrorCastHandle = castHandle;
    SLOGI("mirrorCastHandle is %{public}lld", static_cast<long long>(mirrorCastHandle));
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("SetStreamState failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("SetStreamState failed for the hwCastProviderSession is nullptr");
        return false;
    }
    return hwCastProviderSession->SetStreamState(deviceInfo);
}

bool HwCastProvider::GetRemoteNetWorkId(int32_t castId, std::string deviceId, std::string &networkId)
{
    SLOGI("enter GetRemoteNetWorkId");
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("GetRemoteNetWorkId failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("GetRemoteNetWorkId failed for the hwCastProviderSession is nullptr");
        return false;
    }
    return hwCastProviderSession->GetRemoteNetWorkId(deviceId, networkId);
}

bool HwCastProvider::GetRemoteDrmCapabilities(int32_t castId, std::string deviceId,
    std::vector<std::string> &drmCapabilities)
{
    SLOGI("enter GetRemoteDrmCapabilities");
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("GetRemoteDrmCapabilities failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("GetRemoteDrmCapabilities failed for the hwCastProviderSession is nullptr");
        return false;
    }
    return hwCastProviderSession->GetRemoteDrmCapabilities(deviceId, drmCapabilities);
}

int64_t HwCastProvider::GetMirrorCastHandle()
{
    return mirrorCastHandle;
}

void HwCastProvider::SetMirrorCastHandle(int64_t castHandle)
{
    SLOGI("SetMirrorCastHandle castHandle is %{public}lld", static_cast<long long>(castHandle));
    mirrorCastHandle = castHandle;
}

bool HwCastProvider::RegisterCastSessionStateListener(int castId,
    std::shared_ptr<IAVCastSessionStateListener> listener)
{
    SLOGD("RegisterCastSessionStateListener for castId %{public}d", castId);
    if (listener == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("register castsession state listener check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("RegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("RegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->RegisterCastSessionStateListener(listener);
}

bool HwCastProvider::UnRegisterCastSessionStateListener(int castId,
    std::shared_ptr<IAVCastSessionStateListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return false;
    }
    std::lock_guard lockGuard(mutexLock_);
    SLOGI("unregister castsession state listener check lock with castId %{public}d", static_cast<int32_t>(castId));
    if (hwCastProviderSessionMap_.find(castId) == hwCastProviderSessionMap_.end()) {
        SLOGE("UnRegisterCastSessionStateListener failed for the castSession corresponding to castId is not exit");
        return false;
    }
    auto hwCastProviderSession = hwCastProviderSessionMap_[castId];
    if (hwCastProviderSession == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the hwCastProviderSession is nullptr");
        return false;
    }

    return hwCastProviderSession->UnRegisterCastSessionStateListener(listener);
}

std::vector<uint32_t> HwCastProvider::ParsePullClients(const std::string& str)
{
    std::vector<uint32_t> ret;

    cJSON* array = cJSON_Parse(str.c_str());
    if (array == nullptr) {
        return ret;
    }
    if (cJSON_IsInvalid(array) || !cJSON_IsArray(array)) {
        SLOGE("pullClients is invalid");
        cJSON_Delete(array);
        return ret;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, array) {
        CHECK_AND_CONTINUE(item != nullptr && !cJSON_IsInvalid(item) &&
            cJSON_IsNumber(item));
        ret.push_back(static_cast<uint32_t>(item->valueint));
    }
    cJSON_Delete(array);
    return ret;
}

void HwCastProvider::OnDeviceFound(const std::vector<CastRemoteDevice> &deviceList)
{
    std::vector<DeviceInfo> deviceInfoList;
    if (deviceList.empty()) {
        SLOGW("recv empty deviceList, return");
        return;
    }
    SLOGI("get deviceList size %{public}zu", deviceList.size());
    for (const CastRemoteDevice& castRemoteDevice : deviceList) {
        SLOGI("get devices with deviceName %{public}s", castRemoteDevice.deviceName.c_str());
        DeviceInfo deviceInfo;
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
        deviceInfo.deviceId_ = castRemoteDevice.deviceId;
        deviceInfo.deviceName_ = castRemoteDevice.deviceName;
        deviceInfo.deviceType_ = static_cast<int>(castRemoteDevice.deviceType);
        deviceInfo.ipAddress_ = castRemoteDevice.ipAddress;
        deviceInfo.networkId_ = castRemoteDevice.networkId;
        deviceInfo.manufacturer_ = castRemoteDevice.manufacturerName;
        deviceInfo.modelName_ = castRemoteDevice.modelName;
        deviceInfo.supportedProtocols_ = GetProtocolType(castRemoteDevice.protocolCapabilities);
        deviceInfo.authenticationStatus_ = castRemoteDevice.isTrushed ? TRUSTED_DEVICE : UNTRUSTED_DEVICE;
        deviceInfo.supportedDrmCapabilities_ = castRemoteDevice.drmCapabilities;
        deviceInfo.isLegacy_ = castRemoteDevice.isLeagacy;
        deviceInfo.mediumTypes_ = static_cast<int32_t>(castRemoteDevice.mediumTypes);
        SLOGI("castRemoteDevice.streamCapability %{public}s", castRemoteDevice.streamCapability.c_str());
        deviceInfo.supportedPullClients_ = ParsePullClients(castRemoteDevice.streamCapability);
        deviceInfo.bleMac_ = castRemoteDevice.bleMac;
        deviceInfo.uuid_ = castRemoteDevice.uuid;
        deviceInfoList.emplace_back(deviceInfo);
    }
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnDeviceAvailable for registered listeners");
            listener->OnDeviceAvailable(deviceInfoList);
        }
    }
}

void HwCastProvider::OnLogEvent(const int32_t eventId, const int64_t param)
{
    SLOGI("eventId is %{public}d, param is %{public}" PRId64, eventId, param);
    std::lock_guard lockGuard(mutexLock_);
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnDeviceLogEvent for registered listeners");
            if (eventId == DeviceLogEventCode::DEVICE_LOG_FULL) {
                listener->OnDeviceLogEvent(DeviceLogEventCode::DEVICE_LOG_FULL, param);
            } else {
                listener->OnDeviceLogEvent(DeviceLogEventCode::DEVICE_LOG_EXCEPTION, param);
            }
        }
    }
}

void HwCastProvider::OnDeviceOffline(const std::string& deviceId)
{
    SLOGI("Received on device offline event");
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnDeviceOffline for registered listeners");
            listener->OnDeviceOffline(deviceId);
        }
    }
}

void HwCastProvider::NotifyCastSessionCreated(const std::string castSessionId)
{
    std::shared_ptr<ICastSession> castSession = nullptr;
    CastSessionManager::GetInstance().GetCastSession(castSessionId, castSession);
    CHECK_AND_RETURN_LOG(castSession != nullptr, "get cast session failed");
    SLOGI("Cast provider received session create common event");
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this, castSession]() {
        SLOGI("Cast pvd received session create event and create task thread");
        for (auto listener : castStateListenerList_) {
            listener->OnSessionNeedDestroy();
            SLOGI("Cast pvd received session create event and session destroy check done");
        }
        int32_t castId;
        {
            std::lock_guard lockGuard(mutexLock_);
            std::vector<bool>::iterator iter = find(castFlag_.begin(), castFlag_.end(), false);
            if (iter == castFlag_.end()) {
                SLOGE("Do not trigger callback due to the castFlag_ used up.");
                return;
            }
            *iter = true;
            castId = iter - castFlag_.begin();
            SLOGI("Cast task thread to find flag");
        }
        auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
        hwCastProviderSession->Init();
        hwCastProviderSession->SetCastSource(false);
        {
            std::lock_guard lockGuard(mutexLock_);
            hwCastProviderSessionMap_[castId] = hwCastProviderSession;
            SLOGI("Cast task thread not to create player");
        }
        SLOGI("Create streamPlayer finished %{public}d", castId);
        for (auto listener : castStateListenerList_) {
            listener->OnSessionCreated(castId);
        }
        SLOGI("do session create notify finished %{public}d", castId);
        }, "OnSessionCreated", 0);
}

void HwCastProvider::OnSessionCreated(const std::shared_ptr<CastEngine::ICastSession> &castSession)
{
    SLOGI("Cast provider received session create event");
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this, castSession]() {
        SLOGI("Cast pvd received session create event and create task thread");
        for (auto listener : castStateListenerList_) {
            listener->OnSessionNeedDestroy();
            SLOGI("Cast pvd received session create event and session destroy check done");
        }
        int32_t castId;
        {
            std::lock_guard lockGuard(mutexLock_);
            std::vector<bool>::iterator iter = find(castFlag_.begin(), castFlag_.end(), false);
            if (iter == castFlag_.end()) {
                SLOGE("Do not trigger callback due to the castFlag_ used up.");
                return;
            }
            *iter = true;
            castId = iter - castFlag_.begin();
            SLOGI("Cast task thread to find flag");
        }
        auto hwCastProviderSession = std::make_shared<HwCastProviderSession>(castSession);
        hwCastProviderSession->Init();
        {
            std::lock_guard lockGuard(mutexLock_);
            hwCastProviderSessionMap_[castId] = hwCastProviderSession;
            SLOGI("Cast task thread to create player");
            std::shared_ptr<IStreamPlayer> streamPlayer = hwCastProviderSession->CreateStreamPlayer();
            std::shared_ptr<HwCastStreamPlayer> hwCastStreamPlayer = std::make_shared<HwCastStreamPlayer>(streamPlayer);
            hwCastStreamPlayer->Init();
            avCastControllerMap_[castId] = hwCastStreamPlayer;
        }
        SLOGI("Create streamPlayer finished %{public}d", castId);
        for (auto listener : castStateListenerList_) {
            listener->OnSessionCreated(castId);
        }
        SLOGI("do session create notify finished %{public}d", castId);
        }, "OnSessionCreated", 0);
}

void HwCastProvider::OnServiceDied()
{
    for (auto listener : castStateListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnServiceDied for registered listeners");
            listener->OnCastServerDied();
        }
    }
}

int32_t HwCastProvider::GetProtocolType(uint32_t castProtocolType)
{
    int32_t protocolType = (castProtocolType & ProtocolType::TYPE_CAST_PLUS_STREAM) |
        (castProtocolType & ProtocolType::TYPE_DLNA) |
        ((castProtocolType & static_cast<int>(CastEngine::ProtocolType::CAST_PLUS_AUDIO)) ?
            ProtocolType::TYPE_CAST_PLUS_AUDIO : 0);
    return protocolType;
}

int HwCastProvider::GetCastProtocolType(int castCapability)
{
    uint32_t capability = static_cast<uint32_t>(castCapability);
    int castProtocolType = static_cast<int>((capability & ProtocolType::TYPE_CAST_PLUS_MIRROR ?
        static_cast<uint32_t>(CastEngine::ProtocolType::CAST_PLUS_MIRROR) : 0) |
        (capability & ProtocolType::TYPE_CAST_PLUS_STREAM ?
        static_cast<uint32_t>(CastEngine::ProtocolType::CAST_PLUS_STREAM) : 0) |
        (capability & ProtocolType::TYPE_DLNA ? static_cast<uint32_t>(CastEngine::ProtocolType::DLNA) : 0) |
        (capability & ProtocolType::TYPE_CAST_PLUS_AUDIO ?
        static_cast<uint32_t>(CastEngine::ProtocolType::CAST_PLUS_AUDIO) : 0));
    return castProtocolType;
}
} // namespace OHOS::AVSession
