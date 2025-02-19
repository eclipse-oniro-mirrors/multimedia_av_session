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

#include <gtest/gtest.h>
#include <fstream>
#include "avsession_descriptor.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_service.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS::AVSession {
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static sptr<AVSessionService> g_AVSessionService;

class AVSessionServiceSupplementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceSupplementTest::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTest with OnStart");
    system("killall -9 com.example.hiMusicDemo");
    g_AVSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID, true);
    g_AVSessionService->OnStart();
    SLOGI("set up AVSessionServiceTest done");
}

void AVSessionServiceSupplementTest::TearDownTestCase()
{
    SLOGI("tear down AVSessionServiceTest");
}

void AVSessionServiceSupplementTest::SetUp()
{
}

void AVSessionServiceSupplementTest::TearDown()
{
}

/**
 * @tc.name: GetService001
 * @tc.desc: Test GetService
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetService001, TestSize.Level1)
{
    SLOGI("GetService001 begin!");
    std::string id = "";
    auto ret = g_AVSessionService->GetService(id);
    EXPECT_NE(ret, nullptr);
    SLOGI("GetService001 end!");
}

/**
 * @tc.name: IsLocalDevice001
 * @tc.desc: Test IsLocalDevice
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, IsLocalDevice001, TestSize.Level1)
{
    SLOGI("IsLocalDevice001 begin!");
    std::string id;
    int32_t getSuccess = g_AVSessionService->GetLocalNetworkId(id);
    EXPECT_NE(getSuccess, AVSESSION_SUCCESS);
    bool ret = g_AVSessionService->IsLocalDevice(id);
    EXPECT_EQ(ret, true);
    SLOGI("IsLocalDevice001 end!");
}

/**
 * @tc.name: GetTrustedDeviceName001
 * @tc.desc: Test GetTrustedDeviceName
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetTrustedDeviceName001, TestSize.Level1)
{
    SLOGI("GetTrustedDeviceName001 begin!");
    std::string networkId = "";
    std::string deviceName = "";
    int32_t ret = g_AVSessionService->GetTrustedDeviceName(networkId, deviceName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetTrustedDeviceName001 end!");
}

/**
 * @tc.name: SetDeviceInfo001
 * @tc.desc: Test SetDeviceInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SetDeviceInfo001, TestSize.Level1)
{
    SLOGI("SetDeviceInfo001 begin!");
    AudioStandard::AudioDeviceDescriptor descriptor;
    std::vector<AudioStandard::AudioDeviceDescriptor> castAudioDescriptors;
    castAudioDescriptors.push_back(descriptor);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);
    
    EXPECT_NE(avsessionItem, nullptr);

    g_AVSessionService->SetDeviceInfo(castAudioDescriptors, avsessionItem);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("SetDeviceInfo001 end!");
}

/**
 * @tc.name: GetAudioDescriptorByDeviceId001
 * @tc.desc: Test GetAudioDescriptorByDeviceId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetAudioDescriptorByDeviceId001, TestSize.Level1)
{
    SLOGI("GetAudioDescriptorByDeviceId001 begin!");
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descriptors;
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> descriptor =
        std::make_shared<AudioStandard::AudioDeviceDescriptor>();
    descriptors.push_back(descriptor);
    std::string deviceId = "0";
    AudioStandard::AudioDeviceDescriptor audioDescriptor;
    bool ret = g_AVSessionService->GetAudioDescriptorByDeviceId(descriptors, deviceId, audioDescriptor);
    EXPECT_EQ(ret, true);
    SLOGI("GetAudioDescriptorByDeviceId001 end!");
}

/**
 * @tc.name: GetAudioDescriptorByDeviceId002
 * @tc.desc: Test GetAudioDescriptorByDeviceId
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetAudioDescriptorByDeviceId002, TestSize.Level1)
{
    SLOGI("GetAudioDescriptorByDeviceId002 begin!");
    std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> descriptors;
    std::shared_ptr<AudioStandard::AudioDeviceDescriptor> descriptor =
        std::make_shared<AudioStandard::AudioDeviceDescriptor>();
    descriptors.push_back(descriptor);
    std::string deviceId = "1";
    AudioStandard::AudioDeviceDescriptor audioDescriptor;
    bool ret = g_AVSessionService->GetAudioDescriptorByDeviceId(descriptors, deviceId, audioDescriptor);
    EXPECT_EQ(ret, false);
    SLOGI("GetAudioDescriptorByDeviceId002 end!");
}

/**
 * @tc.name: GetDeviceInfo001
 * @tc.desc: Test GetDeviceInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetDeviceInfo001, TestSize.Level1)
{
    SLOGI("GetDeviceInfo001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::vector<AudioStandard::AudioDeviceDescriptor> castSinkDescriptors;
    std::vector<AudioStandard::AudioDeviceDescriptor> cancelSinkDescriptors;
    std::vector<AudioStandard::AudioDeviceDescriptor> descriptors;
    AudioStandard::AudioDeviceDescriptor descriptor;
    descriptors.push_back(descriptor);

    g_AVSessionService->GetDeviceInfo(avsessionItem,
        descriptors, castSinkDescriptors, cancelSinkDescriptors);
    EXPECT_EQ(castSinkDescriptors.size(), descriptors.size());
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("GetDeviceInfo001 end!");
}

/**
 * @tc.name: GetDeviceInfo002
 * @tc.desc: Test GetDeviceInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, GetDeviceInfo002, TestSize.Level1)
{
    SLOGI("GetDeviceInfo002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::vector<AudioStandard::AudioDeviceDescriptor> castSinkDescriptors;
    std::vector<AudioStandard::AudioDeviceDescriptor> cancelSinkDescriptors;
    std::vector<AudioStandard::AudioDeviceDescriptor> descriptors;

    g_AVSessionService->GetDeviceInfo(avsessionItem,
        descriptors, castSinkDescriptors, cancelSinkDescriptors);
    EXPECT_EQ(descriptors.size(), 0);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("GetDeviceInfo002 end!");
}

/**
 * @tc.name: CastAudioProcess001
 * @tc.desc: Test CastAudioProcess
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, CastAudioProcess001, TestSize.Level1)
{
    SLOGI("CastAudioProcess001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::vector<AudioStandard::AudioDeviceDescriptor> descriptors;
    AudioStandard::AudioDeviceDescriptor descriptor;
    descriptors.push_back(descriptor);

    std::string sourceSessionInfo = "";
    int32_t ret = g_AVSessionService->CastAudioProcess(descriptors,
        sourceSessionInfo, avsessionItem);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("CastAudioProcess001 end!");
}

/**
 * @tc.name: CastAudioProcess002
 * @tc.desc: Test CastAudioProcess
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, CastAudioProcess002, TestSize.Level1)
{
    SLOGI("CastAudioProcess002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    AudioStandard::AudioDeviceDescriptor descriptor;
    std::vector<AudioStandard::AudioDeviceDescriptor> setDescriptors;
    setDescriptors.push_back(descriptor);
    g_AVSessionService->SetDeviceInfo(setDescriptors, avsessionItem);
    
    std::string sourceSessionInfo = "";
    int32_t ret = g_AVSessionService->CastAudioProcess(setDescriptors,
        sourceSessionInfo, avsessionItem);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("CastAudioProcess002 end!");
}

/**
 * @tc.name: IsHistoricalSession001
 * @tc.desc: Test IsHistoricalSession
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, IsHistoricalSession001, TestSize.Level1)
{
    SLOGI("IsHistoricalSession001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string id = "*****";
    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    ofs << id;
    ofs.close();

    bool ret = g_AVSessionService->IsHistoricalSession(id);
    EXPECT_EQ(ret, true);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("IsHistoricalSession001 end!");
}

/**
 * @tc.name: IsHistoricalSession002
 * @tc.desc: Test IsHistoricalSession
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, IsHistoricalSession002, TestSize.Level1)
{
    SLOGI("IsHistoricalSession002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string sessionId = avsessionItem->GetSessionId();
    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::ofstream ofs;
    ofs.open(filePath, std::ios::out);
    ofs << sessionId;
    ofs.close();

    bool ret = g_AVSessionService->IsHistoricalSession(sessionId);
    EXPECT_EQ(ret, false);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("IsHistoricalSession002 end!");
}

/**
 * @tc.name: Dump001
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, Dump001, TestSize.Level1)
{
    SLOGI("Dump001 with OnStartProcess begin!");
    std::vector<std::u16string> argsList;
    g_AVSessionService->OnStartProcess();
    int32_t ret = g_AVSessionService->Dump(1, argsList);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Dump001 end!");
}

/**
 * @tc.name: Dump002
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, Dump002, TestSize.Level1)
{
    SLOGI("Dump002 with OnStartProcess begin!");
    std::vector<std::u16string> argsList;
    std::u16string str(5, 'a');
    argsList.emplace_back(str);
    g_AVSessionService->OnStartProcess();
    int32_t ret = g_AVSessionService->Dump(1, argsList);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("Dump002 end!");
}

/**
 * @tc.name: SaveStringToFileEx001
 * @tc.desc: Test SaveStringToFile
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SaveStringToFileEx001, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx001 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = "/adcdXYZ123/test5.txt";
    std::string content;
    std::ifstream file(filePath, std::ios_base::in);
    bool ret = g_AVSessionService->SaveStringToFileEx(filePath, content);
    file.close();
    EXPECT_EQ(ret, false);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("SaveStringToFileEx001 end!");
}

/**
 * @tc.name: SaveStringToFileEx002
 * @tc.desc: Test SaveStringToFile
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SaveStringToFileEx002, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::string content;
    bool ret = g_AVSessionService->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, false);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("SaveStringToFileEx002 end!");
}

/**
 * @tc.name: SaveStringToFileEx003
 * @tc.desc: Test SaveStringToFile
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SaveStringToFileEx003, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx003 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::string content = "123456";
    bool ret = g_AVSessionService->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, true);
    avsessionItem->Destroy();
    g_AVSessionService->HandleSessionRelease(avsessionItem->GetSessionId());
    SLOGI("SaveStringToFileEx003 end!");
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
/**
 * @tc.name: SuperLauncher001
 * @tc.desc: Test SuperLauncher
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SuperLauncher001, TestSize.Level1)
{
    SLOGI("SuperLauncher001 begin!");
    std::string devideId = "***";
    std::string extraInfo = "*,**";
    std::vector< std::string > serviceNames = {"HuaweiCast", "HuaweiCast-Dual"};
    std::vector< std::string > states = {"IDLE", "CONNECT_SUCC"};
    for (std::string serviceName : serviceNames) {
        for (std::string state : states) {
            g_AVSessionService->SuperLauncher(devideId, serviceName, extraInfo, state);
        }
    }
    
    EXPECT_EQ(serviceNames.size(), 2);
    SLOGI("SuperLauncher001 end!");
}

/**
 * @tc.name: SuperLauncher002
 * @tc.desc: Test SuperLauncher
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SuperLauncher002, TestSize.Level1)
{
    SLOGI("SuperLauncher002 begin!");
    std::string devideId = "***";
    std::string extraInfo = "***";
    std::string serviceName = "***";
    std::string state = "***";
    g_AVSessionService->SuperLauncher(devideId, serviceName, extraInfo, state);
    EXPECT_EQ(serviceName, "***");
    SLOGI("SuperLauncher002 end!");
}

/**
 * @tc.name: SplitExtraInfo001
 * @tc.desc: Test SplitExtraInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SplitExtraInfo001, TestSize.Level1)
{
    SLOGI("SplitExtraInfo001 begin!");
    std::string info = R"(
        {SUPPORT_MIRROR_TO_STREAM: true},
        {deviceId: ***},
        {deviceName: ***},
        {deviceType: ***}
    )";
    g_AVSessionService->SplitExtraInfo(info);
    EXPECT_NE(info.size(), 0);
    SLOGI("SplitExtraInfo001 end!");
}

/**
 * @tc.name: SplitExtraInfo002
 * @tc.desc: Test SplitExtraInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SplitExtraInfo002, TestSize.Level1)
{
    SLOGI("SplitExtraInfo002 begin!");
    std::string info = R"(
        {SUPPORT_MIRROR_TO_STREAM, false},
        {deviceId, ***},
        {deviceName, ***},
        {deviceType, ***}
        )";
    g_AVSessionService->SplitExtraInfo(info);
    EXPECT_NE(info.size(), 0);
    SLOGI("SplitExtraInfo002 end!");
}

/**
 * @tc.name: SplitExtraInfo003
 * @tc.desc: Test SplitExtraInfo
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceSupplementTest, SplitExtraInfo003, TestSize.Level1)
{
    SLOGI("SplitExtraInfo003 begin!");
    std::string info = "";
    g_AVSessionService->SplitExtraInfo(info);
    EXPECT_EQ(info.size(), 0);
    SLOGI("SplitExtraInfo003 end!");
}

#endif
} // OHOS::AVSession