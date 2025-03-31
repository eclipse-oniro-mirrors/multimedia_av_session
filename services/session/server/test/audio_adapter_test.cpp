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
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>
#include "audio_adapter.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "audio_info.h"
#include "audio_device_info.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using OHOS::AudioStandard::AudioDeviceUsage;
using OHOS::AudioStandard::AudioRendererChangeInfo;
using OHOS::AudioStandard::RendererState;

class AudioAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static constexpr int32_t TEST_CLIENT_UID = 1;
    static constexpr int32_t TEST_CLIENT_PID = 1;
    static constexpr int32_t TEST_SESSION_ID = 2;
    static constexpr int32_t TEST_SESSION_FAIL_ID = -1;
};

void AudioAdapterTest::SetUpTestCase()
{}

void AudioAdapterTest::TearDownTestCase()
{}

void AudioAdapterTest::SetUp()
{}

void AudioAdapterTest::TearDown()
{}

/**
* @tc.name: OnRendererStateChange001
* @tc.desc: verifying the renderer state listener
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, OnRendererStateChange001, TestSize.Level1)
{
    SLOGI("OnRendererStateChange001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    AudioAdapter::GetInstance().OnRendererStateChange(infosExpected);

    ASSERT_NE(infosActual.size(), 0);
    const auto& infoExpected = infosExpected[0];
    const auto& infoActual = infosActual[0];
    EXPECT_EQ(infoExpected->clientUID, infoActual->clientUID);
    EXPECT_EQ(infoExpected->sessionId, infoActual->sessionId);
    EXPECT_EQ(infoExpected->rendererState, infoActual->rendererState);
    SLOGI("OnRendererStateChange001 end!");
}

/**
* @tc.name: MuteAudioStream001
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream001, TestSize.Level1)
{
    SLOGI("MuteAudioStream001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        AudioAdapterTest::TEST_CLIENT_PID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);

    ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_SESSION_FAIL_ID,
        AudioAdapterTest::TEST_SESSION_FAIL_ID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: MuteAudioStream002
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
*/
static HWTEST(AudioAdapterTest, MuteAudioStream002, TestSize.Level1)
{
    SLOGI("MuteAudioStream002 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);

    ret = AudioAdapter::GetInstance().MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MUSIC);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: MuteAudioStream003
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream003, TestSize.Level1)
{
    SLOGI("MuteAudioStream003 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.is2in1_ = true;
    auto ret = audioAdapter.MuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: MuteAudioStream004
* @tc.desc: mute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, MuteAudioStream004, TestSize.Level1)
{
    SLOGI("MuteAudioStream004 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->clientPid = AudioAdapterTest::TEST_CLIENT_PID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.is2in1_ = true;
    auto ret = audioAdapter.MuteAudioStream(AudioAdapterTest::TEST_SESSION_FAIL_ID,
        AudioAdapterTest::TEST_SESSION_FAIL_ID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: UnMuteAudioStream001
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream001, TestSize.Level1)
{
    SLOGI("UnMuteAudioStream001 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto ret = AudioAdapter::GetInstance().UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_NE(ret, AVSESSION_ERROR_BASE);
}

/**
* @tc.name: UnMuteAudioStream002
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream002, TestSize.Level1)
{
    SLOGI("UnMuteAudioStream002 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.is2in1_ = true;
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: UnMuteAudioStream003
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream003, TestSize.Level1)
{
    SLOGI("UnMuteAudioStream003 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.is2in1_ = true;
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: UnMuteAudioStream004
* @tc.desc: unmute audio stream for valid uid TEST_CLIENT_UID
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, UnMuteAudioStream004, TestSize.Level1)
{
    SLOGI("UnMuteAudioStream004 begin!");
    std::shared_ptr<AudioRendererChangeInfo> info = std::make_shared<AudioRendererChangeInfo>();
    info->clientUID = AudioAdapterTest::TEST_CLIENT_UID;
    info->sessionId = AudioAdapterTest::TEST_SESSION_ID;
    info->rendererState = RendererState::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    AudioRendererChangeInfos infosActual;

    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().AddStreamRendererStateListener([&infosActual](const AudioRendererChangeInfos& infos) {
        SLOGI("AddStreamRendererStateListener start!");
        for (const auto& info : infos) {
            std::shared_ptr<AudioRendererChangeInfo> infoActual = std::make_shared<AudioRendererChangeInfo>();
            *infoActual = *info;
            infosActual.push_back(std::move(infoActual));
        }
        SLOGI("AddStreamRendererStateListener end!");
    });
    auto& audioAdapter = AudioAdapter::GetInstance();
    auto ret = audioAdapter.UnMuteAudioStream(AudioAdapterTest::TEST_CLIENT_UID,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
* @tc.name: GetRendererRunning001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning001, TestSize.Level1)
{
    SLOGI("GetRendererRunning001 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_CLIENT_UID);
    SLOGI("GetRendererRunning001 end!");
}

/**
* @tc.name: GetRendererRunning002
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, GetRendererRunning002, TestSize.Level1)
{
    SLOGI("GetRendererRunning002 begin!");
    AudioAdapter::GetInstance().Init();
    AudioAdapter::GetInstance().GetRendererRunning(AudioAdapterTest::TEST_SESSION_FAIL_ID);
    SLOGI("GetRendererRunning002 end!");
}

/**
* @tc.name: PauseAudioStream001
* @tc.desc: Test GetRendererRunning
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST(AudioAdapterTest, PauseAudioStream001, TestSize.Level1)
{
    SLOGD("PauseAudioStream001 begin!");
    AudioAdapter::GetInstance().Init();
    int32_t uid = 10001;
    OHOS::AudioStandard::StreamUsage streamUsage {};
    int32_t ret = AudioAdapter::GetInstance().PauseAudioStream(uid, streamUsage);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGD("PauseAudioStream001 end!");
}

/**
 * @tc.name: OnPreferredOutputDeviceUpdated001
 * @tc.desc: Notify registered listeners when the preferred audio output device is updated.
 *           This method iterates through all registered listeners and calls their callback functions
 *           with the updated device descriptor.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceUpdated001, TestSize.Level1)
{
    SLOGD("OnPreferredOutputDeviceUpdated001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().AddDeviceChangeListener(
        [&ret] (const AudioDeviceDescriptorsWithSptr &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorsWithSptr desc = audioAdapter.GetAvailableDevices();
    audioAdapter.deviceChangeListeners_ =
        std::vector<OHOS::AVSession::AudioAdapter::PreferOutputDeviceChangeListener>();
    audioAdapter.OnPreferredOutputDeviceUpdated(desc);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnAvailableDeviceChange001
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange001, TestSize.Level1)
{
    SLOGD("OnAvailableDeviceChange001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnAvailableDeviceChange002
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange002, TestSize.Level1)
{
    SLOGD("OnAvailableDeviceChange002 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::DISCONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnAvailableDeviceChange003
 * @tc.desc: Notify registered listener when the available audio output devices are updated.
 *           This method calls registered listener's callback function with the device change action.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnAvailableDeviceChange003, TestSize.Level1)
{
    SLOGD("OnAvailableDeviceChange003 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetAvailableDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().UnsetAvailableDeviceChangeCallback();

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnAvailableDeviceChange(AudioDeviceUsage::MEDIA_OUTPUT_DEVICES, action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnVolumeKeyEvent001
 * @tc.desc: Notify registered listener when the volume is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnVolumeKeyEvent001, TestSize.Level1)
{
    SLOGD("OnVolumeKeyEvent001 begin!");
    int32_t volume = -1;
    AudioAdapter::GetInstance().RegisterVolumeKeyEventCallback(
        [&volume] (int32_t volumeNum) {
        volume = volumeNum;
    });
    
    AudioAdapter::GetInstance().SetVolume(AudioAdapter::GetInstance().GetVolume());
    sleep(1);
    EXPECT_TRUE(volume != -1);
}

/**
 * @tc.name: OnVolumeKeyEvent002
 * @tc.desc: Notify registered listener when the volume is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnVolumeKeyEvent002, TestSize.Level1)
{
    SLOGD("OnVolumeKeyEvent002 begin!");
    int32_t volume = -1;
    AudioAdapter::GetInstance().RegisterVolumeKeyEventCallback(
        [&volume] (int32_t volumeNum) {
        volume = volumeNum;
    });
    AudioAdapter::GetInstance().UnregisterVolumeKeyEventCallback();

    AudioAdapter::GetInstance().SetVolume(AudioAdapter::GetInstance().GetVolume());
    sleep(1);
    EXPECT_TRUE(volume == -1);
}

/**
* @tc.name: OnDeviceChange001
* @tc.desc: Test OnDeviceChange
* @tc.type: FUNC
*/
static HWTEST(AudioAdapterTest, OnDeviceChange001, TestSize.Level1)
{
    SLOGD("PauseAudioStream001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().AddDeviceChangeListener(
        [&ret] (const AudioDeviceDescriptorsWithSptr &desc) {
        ret = desc.empty();
    });
    AudioAdapter::GetInstance().AddDeviceChangeListener(nullptr);

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    AudioAdapter::GetInstance().OnDeviceChange(action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnDeviceChange002
 * @tc.desc: Notify registered listener when the audio output devices are updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnDeviceChange002, TestSize.Level1)
{
    SLOGD("OnDeviceChange002 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetDeviceChangeCallback();

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnDeviceChange(action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnDeviceChange003
 * @tc.desc: Notify registered listener when the audio output devices are updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnDeviceChange003, TestSize.Level1)
{
    SLOGD("OnDeviceChange003 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetDeviceChangeCallback();
    AudioAdapter::GetInstance().UnsetDeviceChangeCallback();

    DeviceChangeAction action = {};
    action.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    auto& audioAdapter = AudioAdapter::GetInstance();
    audioAdapter.OnDeviceChange(action);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnPreferredOutputDeviceChange001
 * @tc.desc: Notify registered listener when the audio preferred device is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceChange001, TestSize.Level1)
{
    SLOGD("OnPreferredOutputDeviceChange001 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetPreferredOutputDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        auto device = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
        ret = device.empty();
    });

    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors availableDevices = audioAdapter.GetAvailableDevices();
    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    audioAdapter.SelectOutputDevice(availableDevices[0]);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OnPreferredOutputDeviceChange002
 * @tc.desc: Notify registered listener when the audio preferred device is updated.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, OnPreferredOutputDeviceChange002, TestSize.Level1)
{
    SLOGD("OnPreferredOutputDeviceChange002 begin!");
    bool ret = false;
    AudioAdapter::GetInstance().SetPreferredOutputDeviceChangeCallback(
        [&ret] (const AudioDeviceDescriptors &desc) {
        auto device = AudioAdapter::GetInstance().GetPreferredOutputDeviceForRendererInfo();
        ret = device.empty();
    });
    AudioAdapter::GetInstance().UnsetPreferredOutputDeviceChangeCallback();

    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptors availableDevices = audioAdapter.GetAvailableDevices();
    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    audioAdapter.SelectOutputDevice(availableDevices[0]);
    sleep(1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SelectOutputDevice001
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice001, TestSize.Level1)
{
    SLOGD("SelectOutputDevice001 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    auto ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: SelectOutputDevice002
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice002, TestSize.Level1)
{
    SLOGD("SelectOutputDevice002 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorsWithSptr availableDevices = audioAdapter.GetAvailableDevices();

    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    auto testDevice = availableDevices[0];
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    desc->deviceCategory_ = testDevice->deviceCategory_;
    desc->deviceType_ = testDevice->deviceType_;
    int32_t ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: SelectOutputDevice003
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice003, TestSize.Level1)
{
    SLOGD("SelectOutputDevice003 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorsWithSptr availableDevices = audioAdapter.GetAvailableDevices();

    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    auto testDevice = availableDevices[0];
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    desc->deviceCategory_ = testDevice->deviceCategory_;
    EXPECT_NE(desc->deviceType_, testDevice->deviceType_);
    int32_t ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: SelectOutputDevice004
 * @tc.desc: Test SelectOutputDevice with a valid device descriptor that matches one available device.
 * @tc.type: FUNC
 * @tc.require: AR000H31KJ
 */
static HWTEST(AudioAdapterTest, SelectOutputDevice004, TestSize.Level1)
{
    SLOGD("SelectOutputDevice004 begin!");
    AudioAdapter::GetInstance().Init();
    auto& audioAdapter = AudioAdapter::GetInstance();
    AudioDeviceDescriptorsWithSptr availableDevices = audioAdapter.GetAvailableDevices();

    CHECK_AND_RETURN_LOG(availableDevices.size() > 0, "No available devices for testing");
    auto testDevice = availableDevices[0];
    AudioDeviceDescriptorWithSptr desc {new OHOS::AudioStandard::AudioDeviceDescriptor()};
    desc->deviceType_ = testDevice->deviceType_;
    desc->deviceCategory_ = OHOS::AudioStandard::BT_HEADPHONE;

    EXPECT_NE(desc->deviceCategory_, testDevice->deviceCategory_);
    int32_t ret = audioAdapter.SelectOutputDevice(desc);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}