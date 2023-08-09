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

#include <gtest/gtest.h>

#define private public
#include "avsession_dumper.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVSessionDumperTest : public testing::Test {
public:
    std::unique_ptr<AVSessionService> avSessionService_ = nullptr;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionDumperTest::SetUpTestCase()
{}

void AVSessionDumperTest::TearDownTestCase()
{}

void AVSessionDumperTest::SetUp()
{
    avSessionService_ = std::make_unique<AVSessionService>(1, true);
}

void AVSessionDumperTest::TearDown()
{}

/**
 * @tc.name: ShowHelp001
 * @tc.desc: Test whether the string returned by showHelp is correct
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowHelp001, TestSize.Level1)
{
    SLOGI("ShowHelp001 begin");
    std::string argsHelp = "-h";
    std::string expectedString;
    std::string actualString;
    expectedString.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-show_metadata               :show all avsession metadata in the system\n")
        .append("-show_session_info           :show information of all sessions\n")
        .append("-show_controller_info        :show information of all controllers \n")
        .append("-show_error_info             :show error information about avsession\n")
        .append("-show_trusted_devices_Info   :show trusted devices Info\n");
    std::vector<std::string> args;
    args.push_back(argsHelp);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, expectedString);
    SLOGI("ShowHelp001 end");
}

/**
 * @tc.name: ShowTrustedDevicesInfo001
 * @tc.desc: Test whether the string returned by ShowTrustedDevicesInfo is correct
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowTrustedDevicesInfo001, TestSize.Level1)
{
    SLOGI("ShowTrustedDevicesInfo001 begin");
    std::string trustedDeviceInfo = "-show_trusted_devices_Info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(trustedDeviceInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowTrustedDevicesInfo001 end");
}

/**
 * @tc.name: ShowSessionInfo001
 * @tc.desc: Test whether the string returned by ShowSessionInfo is correct
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowSessionInfo001, TestSize.Level1)
{
    SLOGI("ShowSessionInfo001 begin");
    std::string showSessionInfo = "-show_session_info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(showSessionInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowSessionInfo001 end");
}

/**
 * @tc.name: ShowControllerInfo001
 * @tc.desc: Test whether the string returned by ShowControllerInfo is correct
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowControllerInfo, TestSize.Level1)
{
    SLOGI("ShowControllerInfo begin");
    std::string showControllerInfo = "-show_controller_info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(showControllerInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowControllerInfo end");
}

/**
 * @tc.name: ShowErrorInfo001
 * @tc.desc: Test whether errorInfo can be obtained
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowErrorInfo001, TestSize.Level1)
{
    SLOGI("ShowErrorInfo001 begin");
    std::string showErrorInfo = "-show_error_info";
    std::string inputString = "This is error info";
    std::string outputString;
    AVSessionDumper dumper;
    dumper.SetErrorInfo(inputString);
    std::vector<std::string> args;
    args.push_back(showErrorInfo);
    dumper.Dump(args, outputString, *avSessionService_);
    EXPECT_EQ(outputString.size() > inputString.size(), true);
    SLOGI("ShowErrorInfo001 end");
}

/**
 * @tc.name: ShowIllegalInfo001
 * @tc.desc: Show illegal info
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, ShowIllegalInfo001, TestSize.Level1)
{
    SLOGI("ShowIllegalInfo001 begin");
    std::string illegalInformation = "AVSession service, enter '-h' for usage.\n";
    std::string illegalArg = "illegalArg";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(illegalArg);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, illegalInformation);
    SLOGI("ShowIllegalInfo001 end");
}

/**
 * @tc.name: Dump001
 * @tc.desc: Test dump function in unexpected situations
 * @tc.type: FUNC
 * @tc.require: I6RW8M
 */
HWTEST_F(AVSessionDumperTest, Dump001, TestSize.Level1)
{
    SLOGI("Dump001 begin");
    std::string illegalInformation = "AVSession service, enter '-h' for usage.\n";
    std::string actualString;
    std::vector<std::string> args;
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, illegalInformation);
    SLOGI("Dump001 end");
}

/**
 * @tc.name: OnDump001
 * @tc.desc: avsession service ondump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, OnDump001, TestSize.Level1)
{
    avSessionService_->OnDump();
}

/**
 * @tc.name: OnStop001
 * @tc.desc: avsession service onstop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, OnStop001, TestSize.Level1)
{
    avSessionService_->OnStop();
}

/**
 * @tc.name: UpdataTopSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, UpdataTopSession001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    auto item = new AVSessionItem(descriptor);
    avSessionService_->UpdateTopSession(item);
}

/**
 * @tc.name: HandleFocusSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, HandleFocusSession001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.uid_ = 1;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 1;
    avSessionService_->HandleFocusSession(info);
}

/**
 * @tc.name: HandleFocusSession002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, HandleFocusSession002, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.uid_ = 1;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    descriptor.uid_ = 2;
    sptr<AVSessionItem> item = new AVSessionItem(descriptor);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 2;
    avSessionService_->GetContainer().AddSession(1, "abilityName", item);
    avSessionService_->HandleFocusSession(info);
}

/**
 * @tc.name: SelectFocusSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SelectFocusSession001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.uid_ = 1;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    descriptor.uid_ = 2;
    descriptor.sessionTag_ = "RemoteCast";
    sptr<AVSessionItem> item1 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName1", item1);
    descriptor.uid_ = 1;
    descriptor.sessionTag_ = "Local";
    sptr<AVSessionItem> item2 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName2", item2);
    descriptor.uid_ = 2;
    descriptor.sessionTag_ = "Local";
    sptr<AVSessionItem> item3 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName3", item3);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 2;
    EXPECT_EQ(avSessionService_->SelectFocusSession(info), true);
}

/**
 * @tc.name: SelectSessionByUid001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SelectSessionByUid001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.uid_ = 1;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    descriptor.uid_ = 1;
    sptr<AVSessionItem> item1 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName1", item1);
    descriptor.uid_ = 2;
    sptr<AVSessionItem> item2 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName2", item2);
    AudioStandard::AudioRendererChangeInfo info;
    info.clientUID = 2;
    EXPECT_EQ(avSessionService_->SelectSessionByUid(info), item2);
}

/**
 * @tc.name: SelectSessionByUid002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SelectSessionByUid002, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.uid_ = 1;
    avSessionService_->topSession_ = new AVSessionItem(descriptor);
    descriptor.uid_ = 1;
    sptr<AVSessionItem> item1 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName1", item1);
    descriptor.uid_ = 2;
    sptr<AVSessionItem> item2 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName2", item2);
    AudioStandard::AudioRendererChangeInfo info;
    info.clientUID = 3;
    EXPECT_EQ(avSessionService_->SelectSessionByUid(info), nullptr);
}

class TestSessionListener : public SessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s created", descriptor.sessionId_.c_str());
    }

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s released", descriptor.sessionId_.c_str());
    }

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        SLOGI("sessionId=%{public}s be top session", descriptor.sessionId_.c_str());
    }

    void OnAudioSessionChecked(const int32_t uid) override
    {
        SLOGI("uid=%{public}d checked", uid);
    }
};

class TestISessionListener : public ISessionListener {
public:
    void OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
    };

    void OnAudioSessionChecked(const int32_t uid) override
    {
    };

    void OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override
    {
    };

    void OnDeviceOffline(const std::string& deviceId) override
    {
    };

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

/**
 * @tc.name: NotifyAudioSessionCheck001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, NotifyAudioSessionCheck001, TestSize.Level1)
{
    TestSessionListener listener;
    avSessionService_->AddInnerSessionListener(&listener);
    sptr<TestISessionListener> iListener = new TestISessionListener();
    avSessionService_->AddSessionListener(1, iListener);
    avSessionService_->NotifyAudioSessionCheck(1);
}

/**
 * @tc.name: GetSessionDescriptorsBySessionId001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetSessionDescriptorsBySessionId001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "sessionId";
    sptr<AVSessionItem> item1 = new AVSessionItem(descriptor);
    avSessionService_->GetContainer().AddSession(1, "abilityName1", item1);
    EXPECT_EQ(avSessionService_->GetSessionDescriptorsBySessionId("sessionId", descriptor), AVSESSION_SUCCESS);
}

/**
 * @tc.name: StartDefaultAbilityByCall001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, StartDefaultAbilityByCall001, TestSize.Level1)
{
    std::string sessionId = "sessionId";
    EXPECT_EQ(avSessionService_->StartDefaultAbilityByCall(sessionId), -1016);
}

/**
 * @tc.name: StartAbilityByCall001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, StartAbilityByCall001, TestSize.Level1)
{
    std::string sessionIdNeeded = "sessionIdNeeded";
    std::string sessionId = "sessionId";
    EXPECT_EQ(avSessionService_->StartAbilityByCall(sessionIdNeeded, sessionId), AVSESSION_ERROR);
}

/**
 * @tc.name: DeleteHistoricalRecord001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, DeleteHistoricalRecord001, TestSize.Level1)
{
    std::string bundleName = "bundleName";
    avSessionService_->DeleteHistoricalRecord(bundleName);
}

/**
 * @tc.name: ServiceDump001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, ServiceDump001, TestSize.Level1)
{
    std::vector<std::u16string> args;
    EXPECT_EQ(avSessionService_->Dump(-1, args), ERR_INVALID_PARAM);
}

/**
 * @tc.name: ServiceDump002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, ServiceDump002, TestSize.Level1)
{
    std::vector<std::u16string> args;
    EXPECT_EQ(avSessionService_->Dump(0, args), ERR_INVALID_PARAM);
}

/**
 * @tc.name: ServiceDump003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, ServiceDump003, TestSize.Level1)
{
    std::vector<std::u16string> args;
    std::u16string str = u"string";
    args.push_back(str);
    avSessionService_->dumpHelper_ = std::make_unique<AVSessionDumper>();
    EXPECT_EQ(avSessionService_->Dump(0, args), ERR_INVALID_PARAM);
}

/**
 * @tc.name: GetService001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetService001, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    EXPECT_EQ(avSessionService_->GetService(deviceId), nullptr);
}

/**
 * @tc.name: IsLocalDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, IsLocalDevice001, TestSize.Level1)
{
    std::string networkId = "networkId";
    EXPECT_EQ(avSessionService_->IsLocalDevice(networkId), true);
}

/**
 * @tc.name: GetTrustedDeviceName001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetTrustedDeviceName001, TestSize.Level1)
{
    std::string networkId = "networkId";
    std::string deviceName = "deviceName";
    EXPECT_EQ(avSessionService_->GetTrustedDeviceName(networkId, deviceName), AVSESSION_SUCCESS);
}

/**
 * @tc.name: SetBasicInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SetBasicInfo001, TestSize.Level1)
{
    std::string basicInfo = "basicInfo";
    EXPECT_EQ(avSessionService_->SetBasicInfo(basicInfo), AVSESSION_ERROR);
}

/**
 * @tc.name: SetDeviceInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SetDeviceInfo001, TestSize.Level1)
{
    std::vector<AudioStandard::AudioDeviceDescriptor> castAudioDescriptors;
    AudioStandard::AudioDeviceDescriptor des;
    castAudioDescriptors.push_back(des);
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "sessionId";
    sptr<AVSessionItem> item1 = new AVSessionItem(descriptor);
    avSessionService_->SetDeviceInfo(castAudioDescriptors, item1);
}

/**
 * @tc.name: GetAudioDescriptorByDeviceId001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetAudioDescriptorByDeviceId001, TestSize.Level1)
{
    std::vector<sptr<AudioStandard::AudioDeviceDescriptor>> castAudioDescriptors;
    sptr<AudioStandard::AudioDeviceDescriptor> des = new AudioStandard::AudioDeviceDescriptor();
    AudioStandard::AudioDeviceDescriptor res;
    des->deviceId_ = 12;
    castAudioDescriptors.push_back(des);
    std::string deviceId = "12";
    EXPECT_EQ(avSessionService_->GetAudioDescriptorByDeviceId(castAudioDescriptors, deviceId, res), true);
}

/**
 * @tc.name: GetAudioDescriptorByDeviceId002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetAudioDescriptorByDeviceId002, TestSize.Level1)
{
    std::vector<sptr<AudioStandard::AudioDeviceDescriptor>> castAudioDescriptors;
    sptr<AudioStandard::AudioDeviceDescriptor> des = new AudioStandard::AudioDeviceDescriptor();
    AudioStandard::AudioDeviceDescriptor res;
    des->deviceId_ = 11;
    castAudioDescriptors.push_back(des);
    std::string deviceId = "12";
    EXPECT_EQ(avSessionService_->GetAudioDescriptorByDeviceId(castAudioDescriptors, deviceId, res), false);
}

/**
 * @tc.name: SelectOutputDevice001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, SelectOutputDevice001, TestSize.Level1)
{
    AudioStandard::AudioDeviceDescriptor des;
    EXPECT_EQ(avSessionService_->SelectOutputDevice(1, des), AVSESSION_ERROR);
}

/**
 * @tc.name: GetAudioDescriptor001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetAudioDescriptor001, TestSize.Level1)
{
    std::vector<AudioStandard::AudioDeviceDescriptor> castAudioDescriptors;
    AudioStandard::AudioDeviceDescriptor des;
    des.deviceId_ = 11;
    castAudioDescriptors.push_back(des);
    std::string deviceId = "12";
    EXPECT_EQ(avSessionService_->GetAudioDescriptor(deviceId, castAudioDescriptors), AVSESSION_ERROR);
}

/**
 * @tc.name: ClearSessionForClientDiedNoLock001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, ClearSessionForClientDiedNoLock001, TestSize.Level1)
{
    avSessionService_->ClearSessionForClientDiedNoLock(1);
}
} // namespace AVSession
} // namespace OHOS
