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
static HWTEST(AudioDeviceManagerTest, InitAudioStateCallback001, TestSize.Level0)
{
    SLOGI("InitAudioStateCallback001 begin!");
    AudioDeviceManager::GetInstance().isRegistered_ = true;
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = nullptr;
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession, deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ == nullptr);
}

/**
 * @tc.name: RegisterPreferedOutputDeviceChangeCallback001
 * @tc.desc: audioPreferedOutputDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, RegisterPreferedOutputDeviceChangeCallback001, TestSize.Level0)
{
    SLOGI("RegisterPreferedOutputDeviceChangeCallback001 begin!");
    AudioDeviceManager::GetInstance().audioPreferedOutputDeviceChangeCallback_
          = std::make_shared<OutputDeviceChangeCallback>();
    AudioDeviceManager::GetInstance().RegisterPreferedOutputDeviceChangeCallback();
    EXPECT_TRUE(AudioDeviceManager::GetInstance().audioPreferedOutputDeviceChangeCallback_ != nullptr);
}

/**
 * @tc.name: RegisterAudioDeviceChangeCallback001
 * @tc.desc: audioDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, RegisterAudioDeviceChangeCallback001, TestSize.Level1)
{
    SLOGI("RegisterAudioDeviceChangeCallback001 begin!");
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_
        = std::make_shared<DeviceChangeCallback>();
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    EXPECT_TRUE(AudioDeviceManager::GetInstance().audioDeviceChangeCallback_ != nullptr);
}

/**
 * @tc.name: RegisterAudioDeviceChangeCallback002
 * @tc.desc: audioDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, RegisterAudioDeviceChangeCallback002, TestSize.Level1)
{
    SLOGI("RegisterAudioDeviceChangeCallback002 begin!");
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_ = nullptr;
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    EXPECT_TRUE(AudioDeviceManager::GetInstance().audioDeviceChangeCallback_ != nullptr);
}

/**
 * @tc.name: UnRegisterAudioDeviceChangeCallback001
 * @tc.desc: audioDeviceChangeCallback_ have registered
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, UnRegisterAudioDeviceChangeCallback001, TestSize.Level1)
{
    SLOGI("UnRegisterAudioDeviceChangeCallback001 begin!");
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_
        = std::make_shared<DeviceChangeCallback>();
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    int32_t ret = AudioDeviceManager::GetInstance().UnRegisterAudioDeviceChangeCallback();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: SendRemoteAvSessionInfo001
 * @tc.desc: fail to send
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, SendRemoteAvSessionInfo001, TestSize.Level0)
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
static HWTEST(AudioDeviceManagerTest, SendRemoteAvSessionInfo002, TestSize.Level0)
{
    SLOGI("SendRemoteAvSessionInfo002 begin!");
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = std::make_shared<MigrateAVSessionServer>();
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().InitAudioStateCallback(migrateAVSession, deviceId);
    AudioDeviceManager::GetInstance().SendRemoteAvSessionInfo(deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ == nullptr);
}

/**
 * @tc.name: ClearRemoteAvSessionInfo001
 * @tc.desc: test ClearRemoteAvSessionInfo
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, ClearRemoteAvSessionInfo001, TestSize.Level0)
{
    SLOGI("ClearRemoteAvSessionInfo001 begin!");
    std::shared_ptr<MigrateAVSessionServer> migrateAVSession = std::make_shared<MigrateAVSessionServer>();
    AudioDeviceManager::GetInstance().migrateSession_ = migrateAVSession;
    std::string deviceId = "test";
    AudioDeviceManager::GetInstance().ClearRemoteAvSessionInfo(deviceId);
    EXPECT_TRUE(AudioDeviceManager::GetInstance().migrateSession_ != nullptr);
}

/**
 * @tc.name: OnDeviceChange001
 * @tc.desc:
 * @tc.type: FUNC
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange001, TestSize.Level1)
{
    SLOGI("OnDeviceChange001 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange002
 * @tc.number:
 * @tc.desc  : 测试当设备描述符列表为空时,函数应打印错误日志并返回
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange002, TestSize.Level0) {
    SLOGI("OnDeviceChange002 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    deviceChangeAction.deviceDescriptors = {};
    EXPECT_EQ(deviceChangeAction.deviceDescriptors.size(), 0);
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange003
 * @tc.number: OnDeviceChangeTest_003
 * @tc.desc  : 测试当第一个设备描述符为空时,函数应打印错误日志并返回
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange003, TestSize.Level0) {
    SLOGI("OnDeviceChange003 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    deviceChangeAction.deviceDescriptors = {nullptr};
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0], nullptr);
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange004
 * @tc.number: OnDeviceChangeTest_004
 * @tc.desc  : 测试当设备连接状态为VIRTUAL_CONNECTED时,函数应打印信息并返回
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange004, TestSize.Level0) {
    SLOGI("OnDeviceChange004 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    auto desc = std::make_shared<OHOS::AudioStandard::AudioDeviceDescriptor>();
    desc->connectState_ = OHOS::AudioStandard::ConnectState::VIRTUAL_CONNECTED;
    deviceChangeAction.deviceDescriptors = {desc};
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->connectState_,
                OHOS::AudioStandard::ConnectState::VIRTUAL_CONNECTED);
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange005
 * @tc.number: OnDeviceChangeTest_005
 * @tc.desc  : 测试当设备类型为DEVICE_TYPE_BLUETOOTH_A2DP且设备分类为BT_CAR时,函数应发送远程音频会话信息
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange005, TestSize.Level0) {
    SLOGI("OnDeviceChange005 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    auto desc = std::make_shared<OHOS::AudioStandard::AudioDeviceDescriptor>();
    desc->connectState_ = OHOS::AudioStandard::ConnectState::CONNECTED;
    desc->deviceType_ = OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP;
    desc->deviceCategory_ = OHOS::AudioStandard::DeviceCategory::BT_CAR;
    deviceChangeAction.deviceDescriptors = {desc};
    deviceChangeAction.type = OHOS::AudioStandard::DeviceChangeType::DISCONNECT;
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceType_,
                OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP);
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceCategory_,
                OHOS::AudioStandard::DeviceCategory::BT_CAR);
    AudioDeviceManager::GetInstance().migrateSession_ = nullptr;
    AudioDeviceManager::GetInstance().deviceId_ = "test";
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange006
 * @tc.number: OnDeviceChangeTest_006
 * @tc.desc  : DEVICE_TYPE_BLUETOOTH_SCO
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange006, TestSize.Level0) {
    SLOGI("OnDeviceChange006 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    auto desc = std::make_shared<OHOS::AudioStandard::AudioDeviceDescriptor>();
    desc->connectState_ = OHOS::AudioStandard::ConnectState::CONNECTED;
    desc->deviceType_ = OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP;
    desc->deviceCategory_ = OHOS::AudioStandard::DeviceCategory::BT_CAR;
    deviceChangeAction.deviceDescriptors = {desc};
    deviceChangeAction.type = OHOS::AudioStandard::DeviceChangeType::CONNECT;
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceType_,
                OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_A2DP);
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceCategory_,
                OHOS::AudioStandard::DeviceCategory::BT_CAR);
    AudioDeviceManager::GetInstance().migrateSession_ = nullptr;
    AudioDeviceManager::GetInstance().deviceId_ = "test";
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}

/**
 * @tc.name  : OnDeviceChange007
 * @tc.number: OnDeviceChangeTest_007
 * @tc.desc  : DEVICE_TYPE_BLUETOOTH_SCO
 */
static HWTEST(AudioDeviceManagerTest, OnDeviceChange007, TestSize.Level0) {
    SLOGI("OnDeviceChange007 begin!");
    OHOS::AudioStandard::DeviceChangeAction deviceChangeAction;
    auto desc = std::make_shared<OHOS::AudioStandard::AudioDeviceDescriptor>();
    desc->connectState_ = OHOS::AudioStandard::ConnectState::CONNECTED;
    desc->deviceType_ = OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_SCO;
    desc->deviceCategory_ = OHOS::AudioStandard::DeviceCategory::BT_CAR;
    deviceChangeAction.deviceDescriptors = {desc};
    deviceChangeAction.type = OHOS::AudioStandard::DeviceChangeType::DISCONNECT;
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceType_,
                OHOS::AudioStandard::DeviceType::DEVICE_TYPE_BLUETOOTH_SCO);
    EXPECT_EQ(deviceChangeAction.deviceDescriptors[0]->deviceCategory_,
                OHOS::AudioStandard::DeviceCategory::BT_CAR);
    AudioDeviceManager::GetInstance().migrateSession_ = nullptr;
    AudioDeviceManager::GetInstance().deviceId_ = "test";
    AudioDeviceManager::GetInstance().RegisterAudioDeviceChangeCallback();
    AudioDeviceManager::GetInstance().audioDeviceChangeCallback_->OnDeviceChange(deviceChangeAction);
}