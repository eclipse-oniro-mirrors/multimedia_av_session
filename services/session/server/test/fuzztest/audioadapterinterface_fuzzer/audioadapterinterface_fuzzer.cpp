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

#include "securec.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>
#include "audio_adapter.h"
#include "audio_system_manager.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "audioadapterinterface_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MIN_SIZE_NUM = 10;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_totalSize = 0;
using TestFunc = function<void()>;

void AudioAdapterTest001()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    auto &audioAdapter = AudioAdapter::GetInstance();

    int32_t volume = provider.ConsumeIntegral<int32_t>();
    audioAdapter.SetVolume(volume);

    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    audioAdapter.MuteAudioStream(uid, pid);
    audioAdapter.UnsetAvailableDeviceChangeCallback();
    auto callback = [](int32_t) {};
    audioAdapter.RegisterVolumeKeyEventCallback(callback);
    audioAdapter.GetVolume();
    audioAdapter.UnsetDeviceChangeCallback();
}

void AudioAdapterTest002()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    OHOS::AudioStandard::VolumeEvent volumeEvent;
    volumeEvent.volumeType = static_cast<OHOS::AudioStandard::AudioVolumeType>(
        provider.ConsumeIntegralInRange<int>(0, 28));
    volumeEvent.volume = provider.ConsumeIntegral<int32_t>();
    volumeEvent.updateUi = provider.ConsumeBool();
    volumeEvent.networkId = provider.ConsumeRandomLengthString();
    volumeEvent.volumeMode = static_cast<OHOS::AudioStandard::AudioVolumeMode>(
        provider.ConsumeIntegralInRange<int>(0, 1));

    auto &audioAdapter = OHOS::AVSession::AudioAdapter::GetInstance();
    auto callbackFunction = [](int32_t volume) {};
    OHOS::AVSession::AudioVolumeKeyEventCallback callback(callbackFunction);
    callback.OnVolumeKeyEvent(volumeEvent);
    audioAdapter.SetDeviceChangeCallback();

    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    audioAdapter.MuteAudioStream(uid, pid);
    audioAdapter.UnsetAvailableDeviceChangeCallback();
    audioAdapter.UnregisterVolumeKeyEventCallback();
    audioAdapter.UnsetPreferredOutputDeviceChangeCallback();
}

void AudioAdapterTest003()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.SetDeviceChangeCallback();
    audioAdapter.UnregisterVolumeKeyEventCallback();

    int32_t uid = provider.ConsumeIntegral<int32_t>();
    audioAdapter.UnMuteAudioStream(uid);
    auto callback = [](int32_t volume) {};
    audioAdapter.RegisterVolumeKeyEventCallback(callback);

    OHOS::AVSession::AudioAdapter::StateListener StateListener;
    audioAdapter.AddStreamRendererStateListener(StateListener);
    audioAdapter.UnsetPreferredOutputDeviceChangeCallback();
}

void AudioAdapterTest004()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t muteUid = provider.ConsumeIntegral<int32_t>();
    OHOS::AudioStandard::StreamUsage muteUsage = static_cast<OHOS::AudioStandard::StreamUsage>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::STREAM_USAGE_MAX));
    int32_t pauseUid = provider.ConsumeIntegral<int32_t>();
    OHOS::AudioStandard::StreamUsage pauseUsage = static_cast<OHOS::AudioStandard::StreamUsage>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::STREAM_USAGE_MAX));

    auto desc = std::make_shared<OHOS::AudioStandard::AudioDeviceDescriptor>();
    desc->deviceRole_ = static_cast<OHOS::AudioStandard::DeviceRole>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::DEVICE_ROLE_MAX));
    desc->deviceType_ = static_cast<OHOS::AudioStandard::DeviceType>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::DEVICE_TYPE_MAX));
    desc->connectState_ = static_cast<OHOS::AudioStandard::ConnectState>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::CONNECTED));
    OHOS::AudioStandard::AudioRendererChangeInfo rendererChangeInfo;
    rendererChangeInfo.rendererState = static_cast<OHOS::AudioStandard::RendererState>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::RENDERER_PAUSED));

    int32_t unmuteUid = provider.ConsumeIntegral<int32_t>();
    OHOS::AudioStandard::StreamUsage unmuteUsage = static_cast<OHOS::AudioStandard::StreamUsage>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::STREAM_USAGE_MAX));

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.GetRendererRunning(uid);
    audioAdapter.MuteAudioStream(muteUid, muteUsage);
    audioAdapter.PauseAudioStream(pauseUid, pauseUsage);
    audioAdapter.SelectOutputDevice(desc);
    OHOS::AVSession::AudioRendererChangeInfos rendererChangeInfos;
    rendererChangeInfos.push_back(std::make_shared<OHOS::AudioStandard::AudioRendererChangeInfo>(rendererChangeInfo));
    audioAdapter.OnRendererStateChange(rendererChangeInfos);
    audioAdapter.UnMuteAudioStream(unmuteUid, unmuteUsage);
}

void AudioAdapterTest005()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    int32_t uid = provider.ConsumeIntegral<int32_t>();
    OHOS::AudioStandard::StreamUsage usage = static_cast<OHOS::AudioStandard::StreamUsage>(
        provider.ConsumeIntegralInRange<int32_t>(0, OHOS::AudioStandard::STREAM_USAGE_MAX));

    auto callback = [](const OHOS::AVSession::AudioDeviceDescriptors&) {};
    OHOS::AVSession::AudioAdapter::PreferOutputDeviceChangeListener listener;

    auto &audioAdapter = OHOS::AVSession::AudioAdapter::GetInstance();
    audioAdapter.MuteAudioStream(uid, usage);
    audioAdapter.PauseAudioStream(uid, usage);
    audioAdapter.SetAvailableDeviceChangeCallback(callback);
    audioAdapter.SetPreferredOutputDeviceChangeCallback(callback);
    audioAdapter.UnMuteAudioStream(uid, usage);
    audioAdapter.AddDeviceChangeListener(listener);
}

void AudioAdapterTest006()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);
    auto &audioAdapter = AudioAdapter::GetInstance();
    int32_t volume = provider.ConsumeIntegral<int32_t>();
    audioAdapter.SetVolume(volume);
    auto allowedPlaybackCallback = [](int32_t, int32_t) ->bool {
        return true;
    };
    audioAdapter.RegisterAllowedPlaybackCallback(allowedPlaybackCallback);

    auto volumeKeyEventCallback = [](int32_t) -> void {};
    audioAdapter.RegisterVolumeKeyEventCallback(volumeKeyEventCallback);
    audioAdapter.GetVolume();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    audioAdapter.UnMuteAudioStream(uid);
    audioAdapter.UnsetAvailableDeviceChangeCallback();
}

void AudioAdapterTest007()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    auto deviceCount = provider.ConsumeIntegralInRange(0, 10);
    AudioDeviceDescriptors deviceDescriptors;
    for (int i = 0; i < deviceCount; ++i) {
        auto desc = std::make_shared<AudioDeviceDescriptor>();
        desc->deviceType_ = static_cast<AudioStandard::DeviceType>(provider.ConsumeIntegralInRange<int>(0,
             AudioStandard::DEVICE_TYPE_MAX));
        desc->deviceRole_ = static_cast<AudioStandard::DeviceRole>(provider.ConsumeIntegralInRange<int32_t>(0,
             AudioStandard::DEVICE_ROLE_MAX));
        desc->connectState_ = static_cast<AudioStandard::ConnectState>(provider.ConsumeIntegralInRange<int32_t>(0, 3));
        deviceDescriptors.push_back(desc);
    }

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.GetPreferredOutputDeviceForRendererInfo();
    audioAdapter.OnPreferredOutputDeviceUpdated(deviceDescriptors);
    audioAdapter.GetAvailableDevices();
    audioAdapter.GetDevices();
    AudioPreferredDeviceChangeCallback callback([] (const AudioDeviceDescriptors& devices) {});
    callback.OnPreferredOutputDeviceUpdated(deviceDescriptors);

    auto desc = std::make_shared<AudioDeviceDescriptor>();
    audioAdapter.FindRenderDeviceForUsage(deviceDescriptors, desc);
}

void AudioAdapterTest008()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    auto& audioAdapter = AudioAdapter::GetInstance();
    auto preferredDevices = audioAdapter.GetPreferredOutputDeviceForRendererInfo();

    bool shouldSetNull = provider.ConsumeBool();
    AudioDeviceDescriptors deviceDescriptors;
    if(!shouldSetNull) {
        size_t numDescriptors = provider.ConsumeIntegralInRange<size_t>(1, 10);
        for (size_t i = 0; i < numDescriptors; ++i) {
            auto descriptor = std::make_shared<AudioDeviceDescriptor>();
            descriptor->deviceType_ = static_cast<AudioStandard::DeviceType>(provider.ConsumeIntegral<int>());
            descriptor->deviceRole_ = static_cast<AudioStandard::DeviceRole>(provider.ConsumeIntegral<int>());
            deviceDescriptors.push_back(descriptor);
        }
    }

    audioAdapter.OnPreferredOutputDeviceUpdated(deviceDescriptors);
    auto availableDevices = audioAdapter.GetAvailableDevices();
    audioAdapter.Init();
    auto devices = audioAdapter.GetDevices();
    AudioDeviceDescriptorWithSptr targetDescriptor = std::make_shared<AudioDeviceDescriptor>();
    targetDescriptor->deviceType_ = static_cast<AudioStandard::DeviceType>(provider.ConsumeIntegral<int>());
    targetDescriptor->deviceRole_ = static_cast<AudioStandard::DeviceRole>(provider.ConsumeIntegral<int>());
    auto foundDevice = audioAdapter.FindRenderDeviceForUsage(availableDevices, targetDescriptor);
}

void AudioAdapterTest009()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    AudioDeviceDescriptor deviceDescriptor;
    deviceDescriptor.deviceRole_ = static_cast<AudioStandard::DeviceRole>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::DEVICE_ROLE_MAX));
    deviceDescriptor.deviceType_ = static_cast<AudioStandard::DeviceType>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::DEVICE_TYPE_MAX));
    AudioStandard::AudioRendererInfo rendererInfo;
    rendererInfo.contentType = static_cast<AudioStandard::ContentType>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::CONTENT_TYPE_ULTRASONIC));
    rendererInfo.streamUsage = static_cast<AudioStandard::StreamUsage>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::STREAM_USAGE_VOICE_CALL_ASSISTANT));
    rendererInfo.rendererFlags = provider.ConsumeIntegral<int32_t>();
    rendererInfo.volumeMode = static_cast<AudioStandard::AudioVolumeMode>(provider.ConsumeIntegralInRange<int>(0, 1));
    rendererInfo.sceneType = provider.ConsumeRandomLengthString();
    rendererInfo.spatializationEnabled = provider.ConsumeBool();
    rendererInfo.pipeType = static_cast<AudioStandard::AudioPipeType>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::PIPE_TYPE_DIRECT_VOIP));
    rendererInfo.samplingRate = static_cast<AudioStandard::AudioSamplingRate>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::SAMPLE_RATE_192000));
    rendererInfo.format = static_cast<AudioStandard::AudioSampleFormat>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::INVALID_WIDTH));
    rendererInfo.encodingType = provider.ConsumeIntegral<uint8_t>();
    rendererInfo.channelLayout = static_cast<AudioStandard::AudioChannelLayout>(provider.ConsumeIntegral<uint64_t>());
    rendererInfo.playerType = static_cast<AudioStandard::PlayerType>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::PLAYER_TYPE_TONE_PLAYER));

    AudioStandard::AudioRendererChangeInfo rendererChangeInfo;
    rendererChangeInfo.rendererState = static_cast<AudioStandard::RendererState>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::RENDERER_PAUSED));
    rendererChangeInfo.rendererInfo = rendererInfo;

    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> deviceDescriptors;
    size_t numDescriptors = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < numDescriptors; ++i) {
        deviceDescriptors.push_back(std::make_shared<AudioStandard::AudioDeviceDescriptor>(deviceDescriptor));
    }

    auto deviceDescriptorWithSptr = std::make_shared<AudioStandard::AudioDeviceDescriptor>(deviceDescriptor);

    AudioRendererChangeInfos rendererChangeInfos;
    rendererChangeInfos.push_back(std::make_shared<AudioStandard::AudioRendererChangeInfo>(rendererChangeInfo));

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.GetPreferredOutputDeviceForRendererInfo();
    audioAdapter.OnPreferredOutputDeviceUpdated(deviceDescriptors);
    audioAdapter.GetAvailableDevices();
    audioAdapter.GetDevices();
    audioAdapter.FindRenderDeviceForUsage(deviceDescriptors, deviceDescriptorWithSptr);
    audioAdapter.OnRendererStateChange(rendererChangeInfos);
}

void AudioAdapterTest010()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    int32_t volume = provider.ConsumeIntegral<int32_t>();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::function<void(int32_t)> volumeKeyEventCallback = [](int32_t){};
    std::function<bool(int32_t, int32_t)> allowedPlaybackCallback = [](int32_t, int32_t) { return true; };

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.SetVolume(volume);
    audioAdapter.SetDeviceChangeCallback();
    audioAdapter.MuteAudioStream(uid, pid);
    audioAdapter.RegisterVolumeKeyEventCallback(volumeKeyEventCallback);
    audioAdapter.RegisterAllowedPlaybackCallback(allowedPlaybackCallback);
    audioAdapter.UnsetDeviceChangeCallback();
}

void AudioAdapterTest011()
{
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);

    auto descriptor = std::make_shared<AudioStandard::AudioDeviceDescriptor>();
    descriptor->deviceType_ = static_cast<AudioStandard::DeviceType>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::DEVICE_TYPE_MAX));
    descriptor->deviceRole_ = static_cast<AudioStandard::DeviceRole>(
        provider.ConsumeIntegralInRange<int>(0, AudioStandard::DEVICE_ROLE_MAX));
    descriptor->networkId_ = provider.ConsumeRandomLengthString();
    descriptor->macAddress_ = provider.ConsumeRandomLengthString();
    descriptor->deviceName_ = provider.ConsumeRandomLengthString();

    AudioDeviceDescriptors devices;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < count; ++i) {
        devices.push_back(descriptor);
    }

    auto &audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.UnregisterVolumeKeyEventCallback();
    audioAdapter.UnsetAvailableDeviceChangeCallback();
    audioAdapter.FindRenderDeviceForUsage(devices, descriptor);

    audioAdapter.SelectOutputDevice(descriptor);
    audioAdapter.GetVolume();
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    audioAdapter.UnMuteAudioStream(uid);
}

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_totalSize = size;
    FuzzedDataProvider provider(RAW_DATA, g_totalSize);
    std::vector<TestFunc> allFuncs = {
        AudioAdapterTest001,
        AudioAdapterTest002,
        AudioAdapterTest003,
        AudioAdapterTest004,
        AudioAdapterTest005,
        AudioAdapterTest006,
        AudioAdapterTest007,
        AudioAdapterTest008,
        AudioAdapterTest009,
        AudioAdapterTest010,
        AudioAdapterTest011
    };

    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t len = allFuncs.size();
    if (len > 0) {
        allFuncs[code % len]();
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < MIN_SIZE_NUM) {
        return 0;
    }
    /* Run your code on data */
    FuzzTest(data, size);
    return 0;
}
