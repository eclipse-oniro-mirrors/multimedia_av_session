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

#include <gtest/gtest.h>

#include "audio_device_manager.h"
#include "avsession_log.h"
#include "migrate_avsession_server.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class AudioDeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AudioDeviceManagerTest::SetUpTestCase() {}

void AudioDeviceManagerTest::TearDownTestCase() {}

void AudioDeviceManagerTest::SetUp() {}

void AudioDeviceManagerTest::TearDown() {}

/**
 * @tc.name: InitAudioStateCallback001
 * @tc.desc: fail to init callback
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, InitAudioStateCallback001, TestSize.Level1)
{
    SLOGI("InitAudioStateCallback001 begin!");
    AudioDeviceManager::GetInstance().isRegistered_ = true;
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = nullptr;
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession, deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ == nullptr);
}

/**
 * @tc.name: RegisterAudioDeviceChangeCallback001
 * @tc.desc: audioDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, RegisterAudioDeviceChangeCallback001, TestSize.Level1)
{
    SLOGI("RegisterAudioDeviceChangeCallback001 begin!");
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_ = std::make_shared<DeviceChangeCallback>();
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    EXPECT_TRUE(AudioDeviceManager::GetInstance().audioDeviceChangeCallback_ != nullptr);
}

/**
 * @tc.name: RegisterPreferedOutputDeviceChangeCallback001
 * @tc.desc: audioPreferedOutputDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, RegisterPreferedOutputDeviceChangeCallback001, TestSize.Level1)
{
    SLOGI("RegisterPreferedOutputDeviceChangeCallback001 begin!");
    AudioDeviceManager::GetInstance().audioPreferedOutputDeviceChangeCallback_
        = std::make_shared<OutputDeviceChangeCallback>();
    AudioDeviceManager::GetInstance().RegisterPreferedOutputDeviceChangeCallback();
    EXPECT_TRUE(AudioDeviceManager::GetInstance().audioPreferedOutputDeviceChangeCallback_ != nullptr);
}

/**
 * @tc.name: SendRemoteAvSessionInfo001
 * @tc.desc: fail to send
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, SendRemoteAvSessionInfo001, TestSize.Level1)
{
    SLOGI("SendRemoteAvSessionInfo001 begin!");
    AudioDeviceManager::GetInstance().migrateSession_ = nullptr;
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ == nullptr);
}

/**
 * @tc.name: SendRemoteAvSessionInfo002
 * @tc.desc: success to send
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, SendRemoteAvSessionInfo002, TestSize.Level1)
{
    SLOGI("SendRemoteAvSessionInfo002 begin!");
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = std::make_shared<MigrateAVSessionServer>();
    AudioDeviceManager::GetInstance().migrateSession_ = migrateAVSession;
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ != nullptr);
}

/**
 * @tc.name: SendRemoteAudioMsg001
 * @tc.desc: migrateAVSession have created
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, SendRemoteAudioMsg001, TestSize.Level1)
{
    SLOGI("SendRemoteAudioMsg001 begin!");
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = std::make_shared<MigrateAVSessionServer>();
    AudioDeviceManager::GetInstance().migrateSession_ = migrateAVSession;
    std::string deviceId = "test";
    std::string msg = "test";
    AudioDeviceManager::GetInstance().SendRemoteAudioMsg(deviceId, msg);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ != nullptr);
}