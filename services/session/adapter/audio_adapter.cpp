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
#include "audio_adapter.h"
#include "audio_system_manager.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "parameters.h"
#include "avsession_users_manager.h"
#include "permission_checker.h"
#include "app_manager_adapter.h"
#include "iservice_registry.h"

namespace OHOS::AVSession {
std::shared_ptr<AudioAdapter> AudioAdapter::instance_;
std::once_flag AudioAdapter::onceFlag_;

AudioAdapter& AudioAdapter::GetInstance()
{
    std::call_once(onceFlag_, [] {
        instance_ = std::make_shared<AudioAdapter>();
    });
    return *instance_;
}

AudioAdapter::AudioAdapter()
{
    SLOGD("construct");
}

AudioAdapter::~AudioAdapter()
{
    SLOGD("destroy");
}

void AudioAdapter::Init()
{
    SLOGI("register audio renderer event listener");
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(
        getpid(), shared_from_this());
    CHECK_AND_PRINT_LOG(ret == 0, "register audio renderer event listener failed!");
    AudioStandard::AudioRendererInfo rendererInfo = {};
    rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    ret = AudioStandard::AudioRoutingManager::GetInstance()->SetPreferredOutputDeviceChangeCallback(
        rendererInfo, shared_from_this());
    CHECK_AND_PRINT_LOG(ret == 0, "register audio device changed event listener failed!");
    is2in1_ = system::GetBoolParameter("const.audio.volume_apply_to_all", false);

    AudioStandard::AudioVolumeType streamType = AudioStandard::AudioVolumeType::STREAM_MUSIC;
    volumeMax_ = AudioStandard::AudioSystemManager::GetInstance()->GetMaxVolume(streamType);
    volumeMin_ = AudioStandard::AudioSystemManager::GetInstance()->GetMinVolume(streamType);
}

void AudioAdapter::AddStreamRendererStateListener(const StateListener& listener)
{
    std::lock_guard lockGuard(listenersLock_);
    listeners_.push_back(listener);
}

void AudioAdapter::AddDeviceChangeListener(const PreferOutputDeviceChangeListener& listener)
{
    deviceChangeListeners_.push_back(listener);
}

int32_t AudioAdapter::MuteAudioStream(int32_t uid, int32_t pid)
{
    if (is2in1_) {
        SLOGI("PC no need mute");
        return AVSESSION_ERROR;
    }
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "get renderer state failed!");
    auto muteRet = AVSESSION_ERROR;
    for (const auto& info : audioRendererChangeInfo) {
        if ((info->clientUID == uid && info->clientPid == pid) &&
            info->rendererState == AudioStandard::RENDERER_RUNNING && !info->backMute &&
            (std::count(BACKGROUND_MUTE_STREAM_USAGE.begin(), BACKGROUND_MUTE_STREAM_USAGE.end(),
                info->rendererInfo.streamUsage) != 0)) {
            SLOGI("mute uid=%{public}d pid=%{public}d stream usage %{public}d renderer state is %{public}d",
                uid, pid, info->rendererInfo.streamUsage, info->rendererState);
            auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
                uid, AudioStandard::StreamSetState::STREAM_MUTE, info->rendererInfo.streamUsage);
            CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "mute uid=%{public}d failed!", uid);
            muteRet = AVSESSION_SUCCESS;
        }
    }
    return muteRet;
}

int32_t AudioAdapter::UnMuteAudioStream(int32_t uid)
{
    if (is2in1_) {
        SLOGI("PC no need unmute");
        return AVSESSION_ERROR;
    }
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret =
        AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "get renderer state failed!");
    for (const auto& info : audioRendererChangeInfo) {
        if (info->clientUID == uid && info->rendererState == AudioStandard::RENDERER_RUNNING && info->backMute) {
            SLOGI("unmute uid=%{public}d stream usage %{public}d renderer state is %{public}d",
                uid, info->rendererInfo.streamUsage, info->rendererState);
            auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
                uid, AudioStandard::StreamSetState::STREAM_UNMUTE, info->rendererInfo.streamUsage);
            CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "unmute uid=%{public}d failed!", uid);
        }
    }
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnMuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    if (is2in1_) {
        SLOGI("PC no need unmute");
        return AVSESSION_ERROR;
    }
    SLOGI("usage unmute uid=%{public}d stream usage %{public}d", uid, usage);
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_UNMUTE, usage);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "unmute uid=%{public}d failed!", uid);
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::MuteAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    if (is2in1_) {
        SLOGI("PC no need mute");
        return AVSESSION_ERROR;
    }
    if (std::count(BACKGROUND_MUTE_STREAM_USAGE.begin(), BACKGROUND_MUTE_STREAM_USAGE.end(), usage) == 0) {
        SLOGI("mute uid=%{public}d stream usage=%{public}d uncontrolled, return", uid, usage);
        return AVSESSION_ERROR;
    }
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_MUTE, usage);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "mute uid=%{public}d failed!", uid);
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::PauseAudioStream(int32_t uid, AudioStandard::StreamUsage usage)
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UpdateStreamState(
        uid, AudioStandard::StreamSetState::STREAM_PAUSE, usage);
    CHECK_AND_RETURN_RET_LOG(ret == 0, AVSESSION_ERROR, "pause uid=%{public}d failed!", uid);
    return AVSESSION_SUCCESS;
}

void AudioAdapter::OnRendererStateChange(const AudioRendererChangeInfos& infos)
{
    std::lock_guard lockGuard(listenersLock_);
    for (const auto& listener : listeners_) {
        if (listener) {
            listener(infos);
        }
    }
}

void AudioAdapter::OnDeviceChange(const DeviceChangeAction& deviceChangeAction)
{
}

void AudioAdapter::OnAvailableDeviceChange(const AudioStandard::AudioDeviceUsage usage,
    const AudioStandard::DeviceChangeAction& deviceChangeAction)
{
    if (AudioStandard::DeviceChangeType::CONNECT == deviceChangeAction.type) {
        SLOGI("receive connect available device change");
    } else {
        SLOGI("receive disconnect available device change");
    }
    AudioDeviceDescriptors deviceDescriptors = GetAvailableDevices();
    for (auto& device : deviceDescriptors) {
        SLOGI("OnDeviceChange output deviceCategory_ %{public}d, deviceType_ %{public}d",
            static_cast<int32_t>(device->deviceCategory_), static_cast<int32_t>(device->deviceType_));
    }
    availableDeviceChangeCallbackFunc_(deviceDescriptors);
}

void AudioAdapter::OnPreferredOutputDeviceUpdated(const AudioDeviceDescriptors& desc)
{
    for (const auto& listener : deviceChangeListeners_) {
        if (listener) {
            listener(desc);
        }
    }
}

bool AudioAdapter::GetRendererRunning(int32_t uid)
{
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> audioRendererChangeInfo;
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(audioRendererChangeInfo);
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "get renderer state failed!");
    for (const auto& info : audioRendererChangeInfo) {
        CHECK_AND_RETURN_RET_LOG(!(info->clientUID == uid && info->rendererState == AudioStandard::RENDERER_RUNNING),
            true, "find uid=%{public}d renderer state is %{public}d", uid, info->rendererState);
    }

    return false;
}

int32_t AudioAdapter::SetVolume(int32_t volume)
{
    AudioStandard::AudioVolumeType streamType = AudioStandard::AudioVolumeType::STREAM_MUSIC;
    int32_t volumeNum = std::min(volumeMax_, std::max(volume, volumeMin_));
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->SetVolume(streamType, volumeNum);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetVolume failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::GetVolume()
{
    AudioStandard::AudioVolumeType streamType = AudioStandard::AudioVolumeType::STREAM_MUSIC;
    return AudioStandard::AudioSystemManager::GetInstance()->GetVolume(streamType);
}

int32_t AudioAdapter::RegisterVolumeKeyEventCallback(const std::function<void(int32_t)>& callback)
{
    volumeCallback_ = std::make_shared<AudioVolumeKeyEventCallback>(callback);
    int32_t ret = AudioStandard::AudioSystemManager::GetInstance()->RegisterVolumeKeyEventCallback(
        getpid(), volumeCallback_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RegisterVolumeKeyEventCallback failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnregisterVolumeKeyEventCallback()
{
    int32_t ret = AudioStandard::AudioSystemManager::GetInstance()->UnregisterVolumeKeyEventCallback(
        getpid(), volumeCallback_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "UnregisterVolumeKeyEventCallback failed");
    return AVSESSION_SUCCESS;
}

AudioDeviceDescriptors AudioAdapter::GetAvailableDevices()
{
    AudioDeviceDescriptors outDeviceDescriptors;
    AudioDeviceDescriptors devices = AudioStandard::AudioRoutingManager::GetInstance()->GetAvailableDevices(
        AudioStandard::AudioDeviceUsage::MEDIA_OUTPUT_DEVICES);
    for (auto& device : devices) {
        SLOGI("GetAvailableDevices output deviceCategory_ %{public}d, deviceType_ %{public}d",
            static_cast<int32_t>(device->deviceCategory_), static_cast<int32_t>(device->deviceType_));
        outDeviceDescriptors.push_back(device);
    }
    return outDeviceDescriptors;
}

int32_t AudioAdapter::SetAvailableDeviceChangeCallback(const AudioDeviceDescriptorsCallbackFunc& callback)
{
    availableDeviceChangeCallbackFunc_ = callback;
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->SetAvailableDeviceChangeCallback(
        AudioStandard::AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, shared_from_this());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAvailableDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnsetAvailableDeviceChangeCallback()
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UnsetAvailableDeviceChangeCallback(
        AudioStandard::AudioDeviceUsage::MEDIA_OUTPUT_DEVICES);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "UnsetAvailableDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::RegisterAllowedPlaybackCallback(const std::function<bool(int32_t, int32_t)>& callback)
{
    playbackCallback_ = std::make_shared<AudioAllowedPlaybackCallback>(callback);
    int32_t ret = AudioStandard::AudioSystemManager::GetInstance()->SetQueryAllowedPlaybackCallback(playbackCallback_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RegisterAllowedPlaybackCallback failed");
    return AVSESSION_SUCCESS;
}

AudioDeviceDescriptors AudioAdapter::GetDevices()
{
    auto devices = AudioStandard::AudioSystemManager::GetInstance()->GetDevices(
        AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG);
    for (auto& device : devices) {
        SLOGI("GetDevices output deviceCategory_ %{public}d, deviceType_ %{public}d",
            static_cast<int32_t>(device->deviceCategory_), static_cast<int32_t>(device->deviceType_));
    }
    return devices;
}

int32_t AudioAdapter::SetDeviceChangeCallback()
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->SetDeviceChangeCallback(
        AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG, shared_from_this());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnsetDeviceChangeCallback()
{
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->UnsetDeviceChangeCallback(
        AudioStandard::DeviceFlag::OUTPUT_DEVICES_FLAG, shared_from_this());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "UnsetDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

AudioDeviceDescriptors AudioAdapter::GetPreferredOutputDeviceForRendererInfo()
{
    AudioStandard::AudioRendererInfo rendererInfo = {};
    rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    AudioDeviceDescriptors outDeviceDescriptors;
    auto ret = AudioStandard::AudioRoutingManager::GetInstance()->GetPreferredOutputDeviceForRendererInfo(
        rendererInfo, outDeviceDescriptors);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AudioDeviceDescriptors{},
        "GetPreferredOutputDeviceForRendererInfo failed");
    for (auto& device : outDeviceDescriptors) {
        SLOGI("preferred output deviceCategory_ %{public}d, deviceType_ %{public}d",
            static_cast<int32_t>(device->deviceCategory_), static_cast<int32_t>(device->deviceType_));
    }
    return outDeviceDescriptors;
}

int32_t AudioAdapter::SetPreferredOutputDeviceChangeCallback(const AudioDeviceDescriptorsCallbackFunc& callback)
{
    preferredDeviceChangeCallback_ = std::make_shared<AudioPreferredDeviceChangeCallback>(callback);
    AudioStandard::AudioRendererInfo rendererInfo = {};
    rendererInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    auto ret = AudioStandard::AudioRoutingManager::GetInstance()->SetPreferredOutputDeviceChangeCallback(
        rendererInfo, preferredDeviceChangeCallback_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetPreferredOutputDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

int32_t AudioAdapter::UnsetPreferredOutputDeviceChangeCallback()
{
    auto ret = AudioStandard::AudioRoutingManager::GetInstance()->UnsetPreferredOutputDeviceChangeCallback();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "UnsetPreferredOutputDeviceChangeCallback failed");
    return AVSESSION_SUCCESS;
}

AudioDeviceDescriptorWithSptr AudioAdapter::FindRenderDeviceForUsage(const AudioDeviceDescriptors& devices,
    const AudioDeviceDescriptorWithSptr& desc)
{
    auto itr = std::find_if(devices.cbegin(), devices.cend(), [&desc](const auto &device) {
        return (desc->deviceType_ == device->deviceType_) &&
            (desc->macAddress_ == device->macAddress_) &&
            (desc->networkId_ == device->networkId_) &&
            (!AudioStandard::IsUsb(desc->deviceType_) || desc->deviceRole_ == device->deviceRole_);
    });
    return itr != devices.cend() ? *itr : nullptr;
}

int32_t AudioAdapter::SelectOutputDevice(const AudioDeviceDescriptorWithSptr& desc)
{
    AudioDeviceDescriptorWithSptr device = FindRenderDeviceForUsage(GetAvailableDevices(), desc);
    CHECK_AND_RETURN_RET_LOG(device != nullptr, AVSESSION_ERROR, "Give device invaild");
    
    AudioDeviceDescriptors deviceDescriptorVector { device };
    auto ret = AudioStandard::AudioSystemManager::GetInstance()->SelectOutputDevice(deviceDescriptorVector);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SelectOutputDevice failed");
    return AVSESSION_SUCCESS;
}
}
