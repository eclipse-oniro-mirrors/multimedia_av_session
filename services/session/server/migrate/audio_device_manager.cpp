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

#include "migrate/audio_device_manager.h"
#include "avsession_event_handler.h"
#include "avsession_log.h"
#include "bluetooth_a2dp_src.h"
#include "migrate_avsession_constant.h"

namespace OHOS::AVSession {
using namespace Bluetooth;

const int DEFAULT_COD = -1;
const int DEFAULT_MAJOR_CLASS = -1;
const int DEFAULT_MAJOR_MINOR_CLASS = -1;
const int32_t DELAY_SET_TIME = 400;
const uint64_t VIRTUAL_DISPLAY_ID = 1000;
const std::vector<int32_t> connectState_ = { static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED) };
AudioDeviceManager &AudioDeviceManager::GetInstance()
{
    static AudioDeviceManager instance;
    return instance;
}

bool AudioDeviceManager::GetSessionInfoSyncState()
{
    bool isSourceAudio = AUDIO_OUTPUT_SOURCE == outputDevice_;
    return carA2dpConnectState_ || isSourceAudio;
}

void AudioDeviceManager::InitAudioStateCallback(std::shared_ptr<MigrateAVSessionServer> migrateAVSession,
    std::string deviceId)
{
    SLOGI("enter RegisterAudioDeviceChangeCallback");
    if (isRegistered_) {
        SLOGW("device change callback already registered");
        return;
    }
    RegisterAudioDeviceChangeCallback();
    RegisterPreferedOutputDeviceChangeCallback();
    RegisterAudioFocusChangeCallback();
    migrateSession_ = migrateAVSession;
    isRegistered_ = true;
    deviceId_ = deviceId;
}

void AudioDeviceManager::UnInitAudioStateCallback()
{
    UnRegisterAudioDeviceChangeCallback();
    UnRegisterPreferedOutputDeviceChangeCallback();
    UnRegisterAudioFocusChangeCallback();
    isRegistered_ = false;
}

void AudioDeviceManager::RegisterAudioDeviceChangeCallback()
{
    SLOGI("enter RegisterAudioDeviceChangeCallback");
    if (audioDeviceChangeCallback_ == nullptr) {
        audioDeviceChangeCallback_ = std::make_shared<DeviceChangeCallback>();
    }
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->SetDeviceChangeCallback(AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG,
        audioDeviceChangeCallback_);
    AudioStandard::AudioRoutingManager *audioRoutingManager =
        AudioStandard::AudioRoutingManager::GetInstance();
    if (audioRoutingManager == nullptr) {
        SLOGE("audioRoutingManager is null");
        return;
    }
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> devices =
        audioRoutingManager->GetAvailableDevices(AudioStandard::AudioDeviceUsage::MEDIA_OUTPUT_DEVICES);
    for (auto& device : devices) {
        if (device != nullptr &&
            AudioStandard::DeviceCategory::BT_CAR == device->deviceCategory_ &&
            AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP == device->deviceType_) {
            carA2dpConnectState_ = true;
            break;
        }
    }
}

void AudioDeviceManager::UnRegisterAudioDeviceChangeCallback()
{
    SLOGI("enter UnRegisterAudioDeviceChangeCallback");
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->UnsetDeviceChangeCallback(AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG);
}

void AudioDeviceManager::RegisterPreferedOutputDeviceChangeCallback()
{
    if (audioPreferedOutputDeviceChangeCallback_ == nullptr) {
        audioPreferedOutputDeviceChangeCallback_ = std::make_shared<OutputDeviceChangeCallback>();
    }
    AudioStandard::AudioRoutingManager *audioRoutingManager =
        AudioStandard::AudioRoutingManager::GetInstance();
    if (audioRoutingManager == nullptr) {
        SLOGE("audioRoutingManager is null");
        return;
    }
    AudioStandard::AudioRendererInfo rendererInfo;
    rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRoutingManager->SetPreferredOutputDeviceChangeCallback(rendererInfo,
        audioPreferedOutputDeviceChangeCallback_);
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> desc;
    audioRoutingManager->GetPreferredOutputDeviceForRendererInfo(rendererInfo, desc);
    if (desc.empty()) {
        SLOGE("no available device");
        return;
    }
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> device = desc[0];
    if (device != nullptr) {
        if (AudioStandard::LOCAL_NETWORK_ID == device->networkId_) {
            outputDevice_ = AUDIO_OUTPUT_SOURCE;
        } else {
            outputDevice_ = AUDIO_OUTPUT_SINK;
        }
    }
}

void AudioDeviceManager::UnRegisterPreferedOutputDeviceChangeCallback()
{
    SLOGI("enter UnRegisterPreferedOutputDeviceChangeCallback");
    AudioStandard::AudioRoutingManager *audioRoutingManager = AudioStandard::AudioRoutingManager::GetInstance();
    if (audioRoutingManager == nullptr) {
        SLOGE("audioRoutingManger is null");
        return;
    }
    audioRoutingManager->UnsetPreferredOutputDeviceChangeCallback();
}

void AudioDeviceManager::SendRemoteAvSessionInfo(const std::string &deviceId)
{
    if (migrateSession_ != nullptr) {
        migrateSession_->SendRemoteControllerList(deviceId);
    }
}

void AudioDeviceManager::SendRemoteAudioMsg(const std::string &deviceId, std::string sessionId, std::string msg)
{
    if (migrateSession_ != nullptr) {
        migrateSession_->SendRemoteControllerInfo(deviceId, sessionId, msg);
    }
}

std::string AudioDeviceManager::GenerateEmptySession()
{
    Json::Value jsonArray(Json::arrayValue);
    Json::Value result;
    result[SESSION_INFO] =
        "OAAAAEJOREwBAAAAEwAAAEMAbwBuAHQAcgBvAGwAbABlAHIAVwBoAGkAdABlAEwAaQBzAHQAAAAU\nAAAAAQAAAA==\n";
    result[VOLUME_INFO] = "";
    result[PACKAGE_NAME] = "";
    result[PLAYER_ID] = "";
    jsonArray[0] = result;
    Json::Value jsonData;
    jsonData[MEDIA_CONTROLLER_LIST] = jsonArray;
    Json::FastWriter writer;
    std::string jsonStr = writer.write(jsonData);
    char header[] = {MSG_HEAD_MODE, SYNC_CONTROLLER_LIST, '\0'};
    std::string msg = std::string(header) + jsonStr;
    return msg;
}

std::string AudioDeviceManager::GetDeviceId()
{
    return deviceId_;
}

int32_t AudioDeviceManager::GetAudioState()
{
    return outputDevice_;
}

void AudioDeviceManager::SetAudioState(int32_t state)
{
    SLOGI("current set audio is %{public}d", state);
    outputDevice_ = state;
}

bool AudioDeviceManager::GetAppDisplayState(pid_t pid)
{
    std::vector<sptr<Rosen::WindowVisibilityInfo>> infos;
    Rosen::WMError ret = Rosen::WindowManagerLite::GetInstance().GetVisibilityWindowInfo(infos);
    if (ret != Rosen::WMError::WM_OK) {
        SLOGE("GetVisibilityWindowInfo failed, ret: %{public}d.", ret);
        return false;
    }
    uint64_t displayId = 0;
    GetAppDisplayId(displayId, pid, infos);
    if (displayId >= VIRTUAL_DISPLAY_ID) {
        return true;
    }
    return false;
}

bool AudioDeviceManager::GetAppDisplayState(std::string sessionId)
{
    std::vector<sptr<Rosen::WindowVisibilityInfo>> infos;
    Rosen::WMError ret = Rosen::WindowManagerLite::GetInstance().GetVisibilityWindowInfo(infos);
    std::vector<AVSessionDescriptor> descriptors;
    migrateSession_->GetAllSessionDescriptors(descriptors);
    if (ret != Rosen::WMError::WM_OK) {
        SLOGE("GetVisibilityWindowInfo failed, ret: %{public}d.", ret);
        return false;
    }
    pid_t currentPid = 0;
    for (auto& device : descriptors) {
        if (sessionId.compare(device.sessionId_) == 0) {
            currentPid = device.pid_;
            break;
        }
    }
    uint64_t displayId = 0;
    GetAppDisplayId(displayId, currentPid, infos);
    SLOGI("current app display %{public}llu", displayId);
    return displayId >= VIRTUAL_DISPLAY_ID;
}

int32_t AudioDeviceManager::GetAppDisplayId(uint64_t &displayId, pid_t currentPid,
    std::vector<sptr<Rosen::WindowVisibilityInfo>> infos)
{
    std::vector<uint64_t> windowIds;
    uint64_t windowId = 0;
    for (auto& window : infos) {
        if (window != nullptr && window->pid_ == currentPid) {
            windowId = window->windowId_;
            windowIds.push_back(window->windowId_);
            break;
        }
    }
    std::unordered_map<uint64_t, Rosen::DisplayId> windowDisplayIdMap;
    auto res = Rosen::WindowManager::GetInstance().GetDisplayIdByWindowId(windowIds, windowDisplayIdMap);
    if (res != Rosen::WMError::WM_OK) {
        SLOGE("GetDisplayIdByWindowId failed, ret: %{public}d", res);
        return AVSESSION_ERROR;
    }
    for (auto& window : windowDisplayIdMap) {
        if (window.first == windowId) {
            displayId = window.second;
            break;
        }
    }
    SLOGI("current app display %{public}llu", displayId);
    return AVSESSION_SUCCESS;
}

void AudioDeviceManager::ProcessVirtualDisplay()
{
    Bluetooth::A2dpSource *a2dpSource = Bluetooth::A2dpSource::GetProfile();
    if (a2dpSource == nullptr) {
        SLOGE("a2dpSource is null");
        return;
    }

    AudioStandard::AudioSystemManager *audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager != nullptr) {
        audioSystemManager->SetMute(AudioStandard::AudioVolumeType::STREAM_MUSIC, true);
    }
    std::vector<BluetoothRemoteDevice> devices;
    a2dpSource->GetDevicesByStates(connectState_, devices);
    for (auto& device : devices) {
        if (GetBtCarCategoryState(device)) {
            DisconnectCarA2dp(device.GetDeviceAddr());
            break;
        }
    }
}

int32_t AudioDeviceManager::DisconnectCarA2dp(std::string addr)
{
    Bluetooth::A2dpSource *a2dpSource = Bluetooth::A2dpSource::GetProfile();
    if (a2dpSource == nullptr) {
        SLOGE("a2dpSource is null");
        return AVSESSION_ERROR;
    }
    SLOGI("disconnect a2dp ret carBleadd %{public}s", addr.c_str());
    Bluetooth::BluetoothRemoteDevice device(addr, 1);
    int32_t ret = a2dpSource->Disconnect(device);
    subjectDisconnect_ = true;
    return ret;
}

bool AudioDeviceManager::GetBtCarCategoryState(const BluetoothRemoteDevice &device)
{
    int cod = DEFAULT_COD;
    int majorClass = DEFAULT_MAJOR_CLASS;
    int majorMinorClass = DEFAULT_MAJOR_MINOR_CLASS;
    bool res = false;
    device.GetDeviceProductType(cod, majorClass, majorMinorClass);
    SLOGI("Device type majorClass: %{public}d, majorMinorClass: %{public}d.", majorClass, majorMinorClass);
    auto pos = bluetoothDeviceCategoryMap_.find(std::make_pair(majorClass, majorMinorClass));
    if (pos != bluetoothDeviceCategoryMap_.end()) {
        res = true;
    }
    return res;
}

bool AudioDeviceManager::GetA2dpDisconnectSub()
{
    return subjectDisconnect_;
}

void AudioDeviceManager::SetA2dpDisconnectSub(bool subject)
{
    subjectDisconnect_ = subject;
}

void AudioDeviceManager::SetCarA2dpState(bool state)
{
    carA2dpConnectState_ = state;
}

bool AudioDeviceManager::GetCarA2dpState()
{
    return carA2dpConnectState_;
}

void AudioDeviceManager::RegisterAudioFocusChangeCallback()
{
    SLOGI("RegisterAudioFocusChangeCallback");
    if (audioFocusInfoCallback_ == nullptr) {
        audioFocusInfoCallback_ = std::make_shared<FocusInfoChangeCallback>();
    }
    AudioStandard::AudioSystemManager *audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->RegisterFocusInfoChangeCallback(audioFocusInfoCallback_);
}

void AudioDeviceManager::UnRegisterAudioFocusChangeCallback()
{
    SLOGI("UnRegisterAudioFocusChangeCallback");
    AudioStandard::AudioSystemManager *audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    audioSystemManager->UnregisterFocusInfoChangeCallback(audioFocusInfoCallback_);
}

void AudioDeviceManager::GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors)
{
    if (migrateSession_ != nullptr) {
        migrateSession_->GetAllSessionDescriptors(descriptors);
    }
}

void AudioDeviceManager::SetVolumeState(bool state)
{
    setVolumeState_ = state;
}

bool AudioDeviceManager::GetVolumeState()
{
    return setVolumeState_;
}

void AudioDeviceManager::SendPlayCmd()
{
    if (migrateSession_ != nullptr) {
        migrateSession_->SendPlayCommand();
    }
}

void DeviceChangeCallback::OnDeviceChange(const AudioStandard::DeviceChangeAction &deviceChangeAction)
{
    SLOGI("receive OnDeviceChange");
    AudioStandard::AudioSystemManager *audioSystemManager =
        AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        SLOGE("audioSystemManager is null");
        return;
    }
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> deviceDescriptors =
        deviceChangeAction.deviceDescriptors;
    for (auto &device : deviceDescriptors) {
        if (device != nullptr &&
            AudioStandard::DeviceCategory::BT_CAR == device->deviceCategory_ &&
            AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP == device->deviceType_) {
            OnCarA2dpStateChange(deviceChangeAction.type);
        }
    }
}

void DeviceChangeCallback::OnCarA2dpStateChange(AudioStandard::DeviceChangeType type)
{
    if (AudioStandard::DeviceChangeType::DISCONNECT == type) {
        std::string deviceId = AudioDeviceManager::GetInstance().GetDeviceId();
        AudioDeviceManager::GetInstance().SetCarA2dpState(false);
        AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
        if (AudioDeviceManager::GetInstance().GetA2dpDisconnectSub()) {
            AVSessionEventHandler::GetInstance().AVSessionPostTask([=]() {
                AudioDeviceManager::GetInstance().SetVolumeState(true);
                AudioDeviceManager::GetInstance().SetA2dpDisconnectSub(false);
                AudioDeviceManager::GetInstance().SendPlayCmd();
                }, "DelaySetState", DELAY_SET_TIME);
        }
    } else {
        AudioDeviceManager::GetInstance().SetVolumeState(false);
        AudioDeviceManager::GetInstance().SetCarA2dpState(true);
    }
}

void OutputDeviceChangeCallback::OnPreferredOutputDeviceUpdated(
    const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc)
{
    SLOGI("receive OnPreferedOutputDeviceUpdated");
    if (desc.empty()) {
        SLOGE("device is empty");
        return;
    }

    auto deviceDesc = desc[0];
    if (deviceDesc == nullptr) {
        SLOGE("device is null");
        return;
    }
    std::string deviceId = AudioDeviceManager::GetInstance().GetDeviceId();
    if (AudioStandard::LOCAL_NETWORK_ID == deviceDesc->networkId_) {
        SLOGI("OutputDeviceUpdated send empty session");
        std::string msg = AudioDeviceManager::GetInstance().GenerateEmptySession();
        AudioDeviceManager::GetInstance().SendRemoteAudioMsg(deviceId, "", msg);
        AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SOURCE);
    } else {
        SLOGI("OutputDeviceUpdated send remote session");
        AudioDeviceManager::GetInstance().SetAudioState(AUDIO_OUTPUT_SINK);
        AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(
            AudioDeviceManager::GetInstance().GetDeviceId());
    }
}

void FocusInfoChangeCallback::OnAudioFocusInfoChange(
    const std::list<std::pair<AudioStandard::AudioInterrupt, AudioStandard::AudioFocuState>>& infoList)
{
    SLOGD("OnAudioFocusInfoChange");
}

void FocusInfoChangeCallback::OnAudioFocusRequested(const AudioStandard::AudioInterrupt& requestedFocus)
{
    SLOGI("avsession OnAudioFocusRequested pid %{public}d", requestedFocus.pid);
    if (AudioStandard::StreamUsage::STREAM_USAGE_MUSIC == requestedFocus.streamUsage ||
        AudioStandard::StreamUsage::STREAM_USAGE_MEDIA == requestedFocus.streamUsage) {
        if (AudioDeviceManager::GetInstance().GetCarA2dpState() &&
            AudioDeviceManager::GetInstance().GetAppDisplayState(static_cast<pid_t>(requestedFocus.pid))) {
            AudioDeviceManager::GetInstance().ProcessVirtualDisplay();
        }
    }
}

void FocusInfoChangeCallback::OnAudioFocusAbandoned(const AudioStandard::AudioInterrupt& abandonFocus)
{
    SLOGD("avsession OnAudioFocusAbandoned");
}
}