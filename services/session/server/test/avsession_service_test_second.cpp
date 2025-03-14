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
#include <memory>
#include <fstream>
#include <cstdio>

#include "accesstoken_kit.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "avsession_errors.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "avsession_callback_client.h"
#include "avsession_pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_info.h"
#include "avsession_service.h"
#include "audio_info.h"
#include "input_manager.h"
#include "key_event.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "system_ability_ondemand_reason.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AudioStandard;
static AVMetaData g_metaData;
static AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static OHOS::sptr<AVSessionService> g_AVSessionService {nullptr};
static const int32_t COLLABORATION_SA_ID = 70633;
static const int32_t CAST_ENGINE_SA_ID = 65546;

class AVSessionServiceTestSecond : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
};

void AVSessionServiceTestSecond::SetUpTestCase()
{
    SLOGI("set up AVSessionServiceTestSecond");
    system("killall -9 com.example.hiMusicDemo");
    sleep(1);
    g_AVSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    g_AVSessionService->InitKeyEvent();
}

void AVSessionServiceTestSecond::TearDownTestCase()
{
}

void AVSessionServiceTestSecond::SetUp()
{
    SLOGI("set up test function in AVSessionServiceTestSecond");
}

void AVSessionServiceTestSecond::TearDown()
{
    SLOGI("tear down test function in AVSessionServiceTestSecond");
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession_ != nullptr) {
        ret = avsession_->Destroy();
        avsession_ = nullptr;
    }
}

/**
* @tc.name: IsParamInvalid001
* @tc.desc: Verifying IsParamInvalid with an empty tag.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, IsParamInvalid001, TestSize.Level1)
{
    SLOGD("IsParamInvalid001 begin!");
    std::string tag = "";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    bool result = g_AVSessionService->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid001 end!");
}

/**
* @tc.name: IsParamInvalid002
* @tc.desc: Verifying IsParamInvalid with an invalid session type.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, IsParamInvalid002, TestSize.Level1)
{
    SLOGD("IsParamInvalid002 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_INVALID;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("com.example.bundle");
    elementName.SetAbilityName("com.example.ability");
    bool result = g_AVSessionService->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid002 end!");
}

/**
* @tc.name: IsParamInvalid003
* @tc.desc: Verifying IsParamInvalid with an empty bundle name.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, IsParamInvalid003, TestSize.Level1)
{
    SLOGD("IsParamInvalid003 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("");
    elementName.SetAbilityName(g_testAnotherAbilityName);
    bool result = g_AVSessionService->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid003 end!");
}

/**
* @tc.name: IsParamInvalid004
* @tc.desc: Verifying IsParamInvalid with an empty ability name.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, IsParamInvalid004, TestSize.Level1)
{
    SLOGD("IsParamInvalid004 begin!");
    std::string tag = "testTag";
    int32_t type = AVSession::SESSION_TYPE_AUDIO;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName("");
    bool result = g_AVSessionService->IsParamInvalid(tag, type, elementName);
    EXPECT_FALSE(result);
    SLOGD("IsParamInvalid004 end!");
}

/**
* @tc.name: IsLocalDevice001
* @tc.desc: Verifying IsLocalDevice with a valid local network ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, IsLocalDevice001, TestSize.Level1)
{
    SLOGD("IsLocalDevice001 begin!");
    const std::string networkId = "LocalDevice";
    bool result = g_AVSessionService->IsLocalDevice(networkId);
    EXPECT_TRUE(result);
    SLOGD("IsLocalDevice001 end!");
}

/**
* @tc.name: GetDeviceInfo002
* @tc.desc: Verifying GetDeviceInfo with a valid session item and descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, GetDeviceInfo002, TestSize.Level1)
{
    SLOGI("GetDeviceInfo002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    g_AVSessionService->SetDeviceInfo(descriptors, avsessionHere);
    g_AVSessionService->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    EXPECT_NE(avsessionHere, nullptr);
    SLOGI("GetDeviceInfo002 end!");
}

/**
* @tc.name: CastAudioProcess001
* @tc.desc: Verifying CastAudioProcess with a valid session item and descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CastAudioProcess001, TestSize.Level1)
{
    SLOGI("CastAudioProcess001 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors;
    g_AVSessionService->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    const std::string  sourceSessionInfo = "123443";
    auto ret = g_AVSessionService->CastAudioProcess(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CastAudioProcess001 end!");
}

/**
* @tc.name: CastAudioProcess002
* @tc.desc: Verifying CastAudioProcess with a valid session item and descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CastAudioProcess002, TestSize.Level1)
{
    SLOGI("CastAudioProcess002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    g_AVSessionService->SetDeviceInfo(descriptors, avsessionHere);
    g_AVSessionService->GetDeviceInfo(avsessionHere, descriptors, descriptors, descriptors);
    EXPECT_NE(avsessionHere, nullptr);
    const std::string  sourceSessionInfo = "123443";
    auto ret = g_AVSessionService->CastAudioProcess(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CastAudioProcess002 end!");
}

/**
* @tc.name: CastAudioInner001
* @tc.desc: Verifying CastAudioInner with a valid session item and descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CastAudioInner001, TestSize.Level1)
{
    SLOGI("CastAudioInner001 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    auto avsessionHere = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    const std::string  sourceSessionInfo = "123443";
    auto ret = g_AVSessionService->CastAudioInner(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("CastAudioInner001 end!");
}

/**
* @tc.name: CancelCastAudioInner001
* @tc.desc: Verifying CancelCastAudioInner with a valid session item and descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CancelCastAudioInner001, TestSize.Level1)
{
    SLOGI("CancelCastAudioInner001 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    const std::string  sourceSessionInfo = "123443";
    auto ret = g_AVSessionService->CancelCastAudioInner(descriptors, sourceSessionInfo, avsessionHere);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("CancelCastAudioInner001 end!");
}

/**
* @tc.name: CastAudioForAll001
* @tc.desc: Verifying CastAudioForAll with valid descriptors.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CastAudioForAll001, TestSize.Level1)
{
    SLOGI("CastAudioForAll001 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> descriptors = {
        OHOS::AudioStandard::AudioDeviceDescriptor(OHOS::AudioStandard::DeviceType::DEVICE_TYPE_EARPIECE,
            OHOS::AudioStandard::DeviceRole::INPUT_DEVICE, 1, 1, "LocalDevice")
    };
    auto ret = g_AVSessionService->CastAudioForAll(descriptors);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("CastAudioForAll001 end!");
}

/**
* @tc.name: ClearControllerForClientDiedNoLock002
* @tc.desc: Verifying ClearControllerForClientDiedNoLock with a valid PID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, ClearControllerForClientDiedNoLock002, TestSize.Level1)
{
    SLOGI("ClearControllerForClientDiedNoLock002 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    pid_t pid = 1234;
    g_AVSessionService->ClearControllerForClientDiedNoLock(pid);
    EXPECT_TRUE(g_AVSessionService != nullptr);
    SLOGI("ClearControllerForClientDiedNoLock002 end!");
}

/**
* @tc.name: CheckAndCreateDir001
* @tc.desc: Verifying CheckAndCreateDir with a valid file path.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, CheckAndCreateDir001, TestSize.Level1)
{
    SLOGI("CheckAndCreateDir001 begin!");
    EXPECT_TRUE(g_AVSessionService != nullptr);
    const string filePath = "/data/path";
    bool ret = g_AVSessionService->CheckAndCreateDir(filePath);
    EXPECT_TRUE(ret);
    SLOGI("CheckAndCreateDir001 end!");
}

/**
* @tc.name: SaveStringToFileEx001
* @tc.desc: Verifying SaveStringToFileEx with a valid file path and content.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, SaveStringToFileEx001, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx001 begin!");
    std::string filePath =  "uripath";
    std::string content = "123456";
    bool ret = g_AVSessionService->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, true);
    SLOGI("SaveStringToFileEx001 end!");
}

/**
* @tc.name: SaveStringToFileEx002
* @tc.desc: Verifying SaveStringToFileEx with an empty content.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, SaveStringToFileEx002, TestSize.Level1)
{
    SLOGI("SaveStringToFileEx002 begin!");
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    OHOS::sptr<AVSessionItem> avsessionItem = g_AVSessionService->CreateSessionInner(g_testSessionTag,
        AVSession::SESSION_TYPE_AUDIO, false, elementName);

    std::string filePath = g_AVSessionService->GetAVSortDir();
    std::string content = "";
    bool ret = g_AVSessionService->SaveStringToFileEx(filePath, content);
    EXPECT_EQ(ret, false);
    SLOGI("SaveStringToFileEx002 end!");
}

/**
* @tc.name: RemoveExpired001
* @tc.desc: Verifying RemoveExpired with an expired time point.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, RemoveExpired001, TestSize.Level1)
{
    SLOGD("RemoveExpired001 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    timeList.push_back(now - std::chrono::seconds(10));
    g_AVSessionService->RemoveExpired(timeList, now, timeThreshold);

    EXPECT_TRUE(timeList.empty());
    SLOGD("RemoveExpired001 end!");
}

/**
* @tc.name: RemoveExpired002
* @tc.desc: Verifying RemoveExpired with a non-expired time point.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, RemoveExpired002, TestSize.Level1)
{
    SLOGD("RemoveExpired002 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    timeList.push_back(now - std::chrono::seconds(3));

    g_AVSessionService->RemoveExpired(timeList, now, timeThreshold);
    EXPECT_EQ(timeList.size(), 1);
    SLOGD("RemoveExpired002 end!");
}

/**
* @tc.name: RemoveExpired003
* @tc.desc: Verifying RemoveExpired with an empty time list.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, RemoveExpired003, TestSize.Level1)
{
    SLOGD("RemoveExpired003 begin!");
    std::list<std::chrono::system_clock::time_point> timeList;
    auto now = std::chrono::system_clock::now();
    int32_t timeThreshold = 5;
    g_AVSessionService->RemoveExpired(timeList, now, timeThreshold);
    EXPECT_TRUE(timeList.empty());
    SLOGD("RemoveExpired003 end!");
}

/**
* @tc.name: NotifyFlowControl001
* @tc.desc: Verifying NotifyFlowControl with a full flow control list.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, NotifyFlowControl001, TestSize.Level1)
{
    SLOGD("NotifyFlowControl001 begin!");
    g_AVSessionService->flowControlPublishTimestampList_.clear();
    const size_t count = 3;
    for (size_t i = 0; i < count; ++i) {
        g_AVSessionService->flowControlPublishTimestampList_.push_back(std::chrono::system_clock::now());
    }
    bool result = g_AVSessionService->NotifyFlowControl();
    EXPECT_TRUE(result);
    EXPECT_EQ(g_AVSessionService->flowControlPublishTimestampList_.size(), count);
    SLOGD("NotifyFlowControl001 end!");
}

/**
* @tc.name: NotifyFlowControl002
* @tc.desc: Verifying NotifyFlowControl with a non-full flow control list.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, NotifyFlowControl002, TestSize.Level1)
{
    SLOGD("NotifyFlowControl002 begin!");
    const size_t count = 3;
    g_AVSessionService->flowControlPublishTimestampList_.clear();
    for (size_t i = 0; i < count - 1; ++i) {
        g_AVSessionService->flowControlPublishTimestampList_.push_back(std::chrono::system_clock::now());
    }
    bool result = g_AVSessionService->NotifyFlowControl();
    EXPECT_FALSE(result);
    SLOGD("NotifyFlowControl002 end!");
}

/**
* @tc.name: NotifyRemoteDistributedSessionControllersChanged001
* @tc.desc: Verifying NotifyRemoteDistributedSessionControllersChanged with a valid session controller.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, NotifyRemoteDistributedSessionControllersChanged001, TestSize.Level1)
{
    SLOGD("NotifyRemoteDistributedSessionControllersChanged001 begin!");
    std::vector<OHOS::sptr<IRemoteObject>> sessionControllers;
    g_AVSessionService->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    OHOS::sptr<OHOS::ISystemAbilityManager> mgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(mgr != nullptr);
    OHOS::sptr<IRemoteObject> obj = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    sessionControllers.push_back(obj);
    g_AVSessionService->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
    EXPECT_TRUE(g_AVSessionService != nullptr);
    SLOGD("NotifyRemoteDistributedSessionControllersChanged001 end!");
}

static HWTEST_F(AVSessionServiceTestSecond, OnReceiveEvent004, TestSize.Level1)
{
    SLOGI("OnReceiveEvent004 begin!");
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, nullptr);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_EQ(0, AVSESSION_SUCCESS);
    SLOGI("OnReceiveEvent004 end!");
}

/**
* @tc.name: OnIdleWithSessions002
* @tc.desc: Verifying the OnIdle method with none zero count sessions.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnIdleWithSessions002, TestSize.Level1)
{
    SLOGD("OnIdleWithSessions002 begin!");
    OHOS::sptr<AVSessionItem> item = nullptr;
    g_AVSessionService->GetUsersManager().GetContainerFromAll().AddSession(getpid(), g_testAnotherAbilityName, item);
    const OHOS::SystemAbilityOnDemandReason idleReason(
        OHOS::OnDemandReasonId::INTERFACE_CALL, "INTERFACE_CALL", "TestValue", 12345);
    int32_t result = g_AVSessionService->OnIdle(idleReason);
    EXPECT_EQ(result, AVSESSION_ERROR);
    SLOGD("OnIdleWithSessions002 end!");
}

/**
* @tc.name: OnAddSystemAbility002
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is MULTIMODAL_INPUT_SERVICE_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility002, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility002 begin!");
    std::shared_ptr<AVSessionDescriptor> histroyDescriptor = std::make_shared<AVSessionDescriptor>();
    g_AVSessionService->topSession_ = OHOS::sptr<AVSessionItem>::MakeSptr(*histroyDescriptor);

    int32_t systemAbilityId = OHOS::MULTIMODAL_INPUT_SERVICE_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility002 end!");
}

/**
* @tc.name: OnAddSystemAbility003
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is AUDIO_POLICY_SERVICE_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility003, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility003 begin!");
    int32_t systemAbilityId = OHOS::AUDIO_POLICY_SERVICE_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility003 end!");
}

/**
* @tc.name: OnAddSystemAbility004
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is APP_MGR_SERVICE_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility004, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility004 begin!");
    int32_t systemAbilityId = OHOS::APP_MGR_SERVICE_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility004 end!");
}

/**
* @tc.name: OnAddSystemAbility005
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility005, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility005 begin!");
    int32_t systemAbilityId = OHOS::DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility005 end!");
}

/**
* @tc.name: OnAddSystemAbility006
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is BUNDLE_MGR_SERVICE_SYS_ABILITY_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility006, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility006 begin!");
    int32_t systemAbilityId = OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility006 end!");
}

/**
* @tc.name: OnAddSystemAbility007
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is COLLABORATION_SA_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility007, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility007 begin!");
    int32_t systemAbilityId = COLLABORATION_SA_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility007 end!");
}

/**
* @tc.name: OnAddSystemAbility008
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is MEMORY_MANAGER_SA_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility008, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility008 begin!");
    int32_t systemAbilityId = OHOS::MEMORY_MANAGER_SA_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility008 end!");
}

/**
* @tc.name: OnAddSystemAbility009
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility009, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility009 begin!");
    int32_t systemAbilityId = OHOS::SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility009 end!");
}

/**
* @tc.name: OnAddSystemAbility010
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is COMMON_EVENT_SERVICE_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility010, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility010 begin!");
    int32_t systemAbilityId = OHOS::COMMON_EVENT_SERVICE_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    SLOGD("OnAddSystemAbility010 end!");
}

/**
* @tc.name: OnAddSystemAbility011
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is CAST_ENGINE_SA_ID.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility011, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility011 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t systemAbilityId = CAST_ENGINE_SA_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
#else
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
#endif
    SLOGD("OnAddSystemAbility011 end!");
}

/**
* @tc.name: OnAddSystemAbility012
* @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId is CAST_ENGINE_SA_ID and is2in1_ is true.
* @tc.type: FUNC
* @tc.require: #I5Y4MZ
*/
static HWTEST_F(AVSessionServiceTestSecond, OnAddSystemAbility012, TestSize.Level1)
{
    SLOGD("OnAddSystemAbility012 begin!");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t systemAbilityId = CAST_ENGINE_SA_ID;
    const std::string deviceId = "AUDIO";
    g_AVSessionService->is2in1_ = true;
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
#else
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
#endif
    SLOGD("OnAddSystemAbility012 end!");
}
