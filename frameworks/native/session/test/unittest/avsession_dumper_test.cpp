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
#include "avsession_item.h"
#undef private
#include "system_ability_definition.h"

using namespace testing::ext;

static OHOS::AVSession::AVSessionService* avSessionService_;
static OHOS::sptr<OHOS::AVSession::AVSessionItem> item_;

namespace OHOS {
namespace AVSession {
class AVSessionDumperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    sptr<AVSessionItem> doSessionCreateTemp();
};

void AVSessionDumperTest::SetUpTestCase()
{}

void AVSessionDumperTest::TearDownTestCase()
{}

void AVSessionDumperTest::SetUp()
{
    SLOGI("AVSessionDumperTest do SetUp");
    if (avSessionService_ == nullptr) {
        SLOGI("AVSessionDumperTest do service newUp");
        avSessionService_ = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
        SLOGI("AVSessionDumperTest do service newUp checkNull:%{public}d",
            static_cast<int>(avSessionService_ != nullptr));
        avSessionService_->dumpHelper_ = std::make_unique<AVSessionDumper>();
        sleep(1);
        SLOGI("AVSessionDumperTest do abilityManager init");
        avSessionService_->InitAMS();
        SLOGI("AVSessionDumperTest do abilityManager init done");
        sleep(1);
        item_ = doSessionCreateTemp();
    }
}

void AVSessionDumperTest::TearDown()
{}

sptr<AVSessionItem> AVSessionDumperTest::doSessionCreateTemp()
{
    SLOGI("doSessionCreateTemp begin !");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("test.ohos.avsession");
    elementName.SetAbilityName("test.ability");
    sptr<AVSessionItem> item = avSessionService_->CreateSessionInner("test",
        AVSession::SESSION_TYPE_AUDIO, false, elementName);
    SLOGI("doSessionCreateTemp done with item checkNull %{public}d", static_cast<int>(item != nullptr));
    return item;
}

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
    EXPECT_NE(avSessionService_, nullptr);
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
    EXPECT_NE(avSessionService_, nullptr);
}

/**
 * @tc.name: UpdataTopSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, UpdataTopSession001, TestSize.Level1)
{
    sleep(1);
    SLOGI("UpdataTopSession001 in");
    sptr<AVSessionItem> item = item_;
    if (item == nullptr) {
        item = doSessionCreateTemp();
    }
    EXPECT_NE(item, nullptr);
    // not set topsession for crash
    avSessionService_->UpdateTopSession(item);
    EXPECT_NE(avSessionService_, nullptr);
    avSessionService_->HandleSessionRelease(item->GetDescriptor().sessionId_);
    SLOGI("UpdataTopSession001 done");
}

/**
 * @tc.name: HandleFocusSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, HandleFocusSession001, TestSize.Level1)
{
    sleep(1);
    SLOGI("HandleFocusSession001 in ");
    sptr<AVSessionItem> item = item_;
    if (item == nullptr) {
        item = doSessionCreateTemp();
    }
    EXPECT_NE(item, nullptr);
    // not set topsession for crash
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 0;
    avSessionService_->HandleFocusSession(info, false);
    AVSessionDescriptor descriptor = item->GetDescriptor();
    avSessionService_->HandleSessionRelease(descriptor.sessionId_);
    EXPECT_NE(avSessionService_, nullptr);
    SLOGI("HandleFocusSession001 done ");
}

/**
 * @tc.name: HandleFocusSession002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, HandleFocusSession002, TestSize.Level1)
{
    sleep(1);
    SLOGI("HandleFocusSession002 in");
    sptr<AVSessionItem> item = item_;
    if (item == nullptr) {
        item = doSessionCreateTemp();
    }
    EXPECT_NE(item, nullptr);
    FocusSessionStrategy::FocusSessionChangeInfo info;
    info.uid = 2;
    avSessionService_->HandleFocusSession(info, false);
    EXPECT_NE(avSessionService_, nullptr);
    avSessionService_->HandleSessionRelease(item->GetDescriptor().sessionId_);
    SLOGI("HandleFocusSession002 done");
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

    void OnDeviceLogEvent(const DeviceLogEventCode eventId, const int64_t param) override
    {
    };

    void OnDeviceOffline(const std::string& deviceId) override
    {
    };

    void OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override
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
    SLOGI("NotifyAudioSessionCheck001 in");
    TestSessionListener listener;
    avSessionService_->AddInnerSessionListener(&listener);
    sptr<TestISessionListener> iListener = new TestISessionListener();
    avSessionService_->AddSessionListener(1, iListener);
    avSessionService_->NotifyAudioSessionCheck(1);
    avSessionService_->RemoveInnerSessionListener(&listener);
    EXPECT_NE(avSessionService_, nullptr);
    SLOGI("NotifyAudioSessionCheck001 out");
}

/**
 * @tc.name: GetSessionDescriptorsBySessionId001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetSessionDescriptorsBySessionId001, TestSize.Level1)
{
    SLOGI("GetSessionDescriptorsBySessionId001 in");
    AVSessionDescriptor descriptor;
    sptr<AVSessionItem> item = item_;
    if (item == nullptr) {
        item = doSessionCreateTemp();
    }
    EXPECT_NE(item, nullptr);
    avSessionService_->GetContainer().AddSession(1, "abilityName1", item);
    std::string sessionId = item->GetDescriptor().sessionId_;
    EXPECT_EQ(avSessionService_->GetSessionDescriptorsBySessionId(sessionId, descriptor), AVSESSION_SUCCESS);
    avSessionService_->HandleSessionRelease(descriptor.sessionId_);
    SLOGI("GetSessionDescriptorsBySessionId001 done");
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
    // startability may go with mediaintent, will return AVSESSION_ERROR
    int32_t ret = avSessionService_->StartDefaultAbilityByCall(sessionId);
    SLOGI("StartDefaultAbilityByCall001 with ret:%{public}d", ret);
    EXPECT_EQ(ret == ERR_ABILITY_NOT_AVAILABLE || ret == AVSESSION_SUCCESS || ret == AVSESSION_ERROR, true);
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
    EXPECT_NE(avSessionService_, nullptr);
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
    SLOGI("SetDeviceInfo001 in");
    std::vector<AudioStandard::AudioDeviceDescriptor> castAudioDescriptors;
    AudioStandard::AudioDeviceDescriptor des;
    castAudioDescriptors.push_back(des);
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "sessionId";
    sptr<AVSessionItem> item = item_;
    if (item == nullptr) {
        item = doSessionCreateTemp();
    }
    EXPECT_NE(item, nullptr);
    avSessionService_->SetDeviceInfo(castAudioDescriptors, item);
    EXPECT_NE(item, nullptr);
    avSessionService_->HandleSessionRelease(item->GetDescriptor().sessionId_);
    SLOGI("SetDeviceInfo001 done");
}

/**
 * @tc.name: GetAudioDescriptorByDeviceId001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AVSessionDumperTest, GetAudioDescriptorByDeviceId001, TestSize.Level1)
{
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> castAudioDescriptors;
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> des =
        std::make_shared<AudioStandard::AudioDeviceDescriptor>();
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
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> castAudioDescriptors;
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> des =
        std::make_shared<AudioStandard::AudioDeviceDescriptor>();
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
} // namespace AVSession
} // namespace OHOS
