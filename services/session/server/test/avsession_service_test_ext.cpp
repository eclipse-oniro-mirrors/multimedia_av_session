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

#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_sysevent.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avsession_info.h"
#include "avsession_service.h"
#include "audio_info.h"
#include "client_death_proxy.h"
#include "system_ability_definition.h"
#include "system_ability_ondemand_reason.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
using namespace OHOS::AudioStandard;

namespace OHOS {
namespace AVSession {

static AVMetaData g_metaData;
static AVPlaybackState g_playbackState;
static char g_testSessionTag[] = "test";
static char g_testAnotherBundleName[] = "testAnother.ohos.avsession";
static char g_testAnotherAbilityName[] = "testAnother.ability";
static OHOS::sptr<AVSessionService> g_AVSessionService {nullptr};
static bool g_isCallOnSessionCreate = false;
static bool g_isCallOnSessionRelease = false;
static bool g_isCallOnTopSessionChange = false;
static const int32_t ANCO_BROKER_SA_ID = 66849;

class TestISessionListener : public ISessionListener {
    TestISessionListener() = default;
    virtual ~TestISessionListener() = default;
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        g_isCallOnSessionCreate = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        g_isCallOnSessionRelease = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        g_isCallOnTopSessionChange = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnAudioSessionChecked(const int32_t uid) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDeviceOffline(const std::string& deviceId) override
    {
        return AVSESSION_SUCCESS;
    };
    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override
    {
        g_isCallOnTopSessionChange = true;
        return AVSESSION_SUCCESS;
    };
    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override
    {
        return AVSESSION_SUCCESS;
    };
    OHOS::sptr<IRemoteObject> AsObject() override { return nullptr; };
};

class TestHistoricalRecordListener : public HistoricalRecordListener {
public:
    TestHistoricalRecordListener()  = default;
    virtual ~TestHistoricalRecordListener() = default;

    void OnHistoricalRecordChange() override
    {
        SLOGI("OnHistoricalRecordChange called");
    }
};

class AVSessionServiceTestExt : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionServiceTestExt::SetUpTestCase()
{
    SLOGD("set up test case AVSessionServiceTestExt");
}

void AVSessionServiceTestExt::TearDownTestCase()
{
    SLOGD("tear down test case AVSessionServiceTestExt");
}

void AVSessionServiceTestExt::SetUp()
{
    SLOGD("set up test function in AVSessionServiceTestExt");
    g_AVSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    g_AVSessionService->InitKeyEvent();
}

void AVSessionServiceTestExt::TearDown()
{
    SLOGD("tear down test function in AVSessionServiceTestExt");
}

/**
 * @tc.name: OnStartProcess001
 * @tc.desc: Test OnStartProcess when normal branch
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, OnStartProcess001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->OnStartProcess();
    EXPECT_EQ(g_AVSessionService->maxHistoryNums_, 10);
}

/**
 * @tc.name: OnReceiveEvent001
 * @tc.desc: Test OnReceiveEvent when action with different property
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, OnReceiveEvent001, TestSize.Level0)
{
    OHOS::EventFwk::CommonEventData eventData;
    string action = OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND;
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, g_AVSessionService);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED;
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED;
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = EventFwk::CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED;
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);
}

/**
 * @tc.name: OnReceiveEvent002
 * @tc.desc: Test OnReceiveEvent when action with different property
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, OnReceiveEvent002, TestSize.Level0)
{
    OHOS::EventFwk::CommonEventData eventData;
    string action = "EVENT_REMOVE_MEDIACONTROLLER_LIVEVIEW";
    OHOS::AAFwk::Want want = eventData.GetWant();
    want.SetAction(action);
    eventData.SetWant(want);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventSubscriber eventSubscriber(subscriberInfo, g_AVSessionService);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);

    action = "EVENT_AVSESSION_MEDIA_CAPSULE_STATE_CHANGE";
    want.SetAction(action);
    eventData.SetWant(want);
    eventSubscriber.OnReceiveEvent(eventData);
    EXPECT_NE(nullptr, eventSubscriber.servicePtr_);
}

/**
 * @tc.name: HandleUserEvent001
 * @tc.desc: Verifying the HandleUserEvent type == AVSessionUsersManager::accountEventSwitched &&
 *           userId != curUserId && hasMediaCapsule_.load()
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, HandleUserEvent001, TestSize.Level0)
{
    int userId = 1001;
    std::string type = AVSessionUsersManager::accountEventSwitched;
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->hasMediaCapsule_.store(true);
    g_AVSessionService->HandleUserEvent(type, userId);
    EXPECT_EQ(g_AVSessionService->hasMediaCapsule_.load(), false);
}

/**
 * @tc.name: HandleMediaCardStateChangeEvent001
 * @tc.desc: Test HandleMediaCardStateChangeEvent when isAppear == "DISAPPEAR"
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, HandleMediaCardStateChangeEvent001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    std::string isAppear = "DISAPPEAR";
    g_AVSessionService->topSession_ = nullptr;
    g_AVSessionService->hasRemoveEvent_.store(true);
    g_AVSessionService->HandleMediaCardStateChangeEvent(isAppear);

    g_AVSessionService->hasRemoveEvent_.store(false);
    g_AVSessionService->HandleMediaCardStateChangeEvent(isAppear);
    EXPECT_TRUE(g_AVSessionService->hasCardStateChangeStopTask_.load());
}

/**
 * @tc.name: OnAddSystemAbility001
 * @tc.desc: Verifying the OnAddSystemAbility method with systemAbilityId == ANCO_BROKER_SA_ID.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, OnAddSystemAbility001, TestSize.Level0)
{
    int32_t systemAbilityId = ANCO_BROKER_SA_ID;
    const std::string deviceId = "AUDIO";
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_TRUE(g_AVSessionService->isAudioBrokerStart_);
}

/**
 * @tc.name: UpdateTopSession001
 * @tc.desc: Verifying the UpdateTopSession method with userIdForNewTopSession !=
 *           GetUsersManager().GetCurrentUserId()
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, UpdateTopSession001, TestSize.Level0)
{
    int32_t userId = 1001;
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->UpdateTopSession(nullptr, userId);
    EXPECT_EQ(g_AVSessionService->topSession_, nullptr);
}

/**
 * @tc.name: HandleChangeTopSession001
 * @tc.desc: Verifying the HandleChangeTopSession method with a invalid infoUid.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, HandleChangeTopSession001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    int32_t infoUid = 123;
    int32_t infoPid = 123;
    avsessionHere->SetUid(infoUid);
    avsessionHere->SetPid(infoPid);
    auto sessionListForFront = std::make_shared<std::list<sptr<AVSessionItem>>>();
    CHECK_AND_RETURN(sessionListForFront != nullptr);
    sessionListForFront->push_front(avsessionHere);
    int32_t curUserId = 100;
    g_AVSessionService->GetUsersManager().frontSessionListMapByUserId_.clear();
    g_AVSessionService->GetUsersManager().frontSessionListMapByUserId_[curUserId] = sessionListForFront;

    avsessionHere->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VIDEO;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, curUserId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    avsessionHere->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VOICE_CALL;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, curUserId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    avsessionHere->descriptor_.sessionType_ = AVSession::SESSION_TYPE_VIDEO_CALL;
    g_AVSessionService->HandleChangeTopSession(infoUid, infoPid, curUserId);
    EXPECT_NE(g_AVSessionService->topSession_, nullptr);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
}

/**
 * @tc.name: LowQualityCheck001
 * @tc.desc: Verifying the LowQualityCheck method with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, LowQualityCheck001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    avsessionHere->metaData_.title_ = "test_title";
    avsessionHere->metaData_.mediaImage_ = nullptr;
    avsessionHere->metaData_.mediaImageUri_ = "test_uri";
    avsessionHere->supportedCmd_.push_back(AVControlCommand::SESSION_CMD_PLAY);
    int32_t uid = 100;
    int32_t pid = 101;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_PAUSED;
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);

    avsessionHere->metaData_.title_ = "";
    avsessionHere->metaData_.mediaImageUri_ = "test_uri";
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);

    avsessionHere->metaData_.title_ = "test_title";
    avsessionHere->metaData_.mediaImageUri_ = "";
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_EQ(g_AVSessionService->topSession_, nullptr);
}

/**
 * @tc.name: LowQualityCheck002
 * @tc.desc: Verifying the LowQualityCheck method with invalid parameters.
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, LowQualityCheck002, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    avsessionHere->metaData_.title_ = "";
    avsessionHere->metaData_.mediaImage_ = nullptr;
    avsessionHere->metaData_.mediaImageUri_ = "";
    avsessionHere->supportedCmd_.push_back(AVControlCommand::SESSION_CMD_INVALID);
    avsessionHere->supportedCmd_.push_back(AVControlCommand::SESSION_CMD_PLAY);

    int32_t uid = 100;
    int32_t pid = 101;
    StreamUsage streamUsage = StreamUsage::STREAM_USAGE_MEDIA;
    RendererState rendererState = RendererState::RENDERER_PAUSED;
    g_AVSessionService->LowQualityCheck(uid, pid, streamUsage, rendererState);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_EQ(g_AVSessionService->topSession_, nullptr);
}

/**
 * @tc.name: CheckAncoAudio001
 * @tc.desc: Verifying the CheckAncoAudio method with session->GetBundleName() == "anco_audio"
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, CheckAncoAudio001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    std::string name = "anco_audio";
    elementName.SetBundleName(name);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    bool ret = g_AVSessionService->CheckAncoAudio();
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetAllSessionDescriptors001
 * @tc.desc: Verfying GetAllSessionDescriptors when the session is nullptr
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, GetAllSessionDescriptors001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    auto sessionListForFront = std::make_shared<std::list<sptr<AVSessionItem>>>();
    CHECK_AND_RETURN(sessionListForFront != nullptr);
    sessionListForFront->push_front(avsessionHere);
    sessionListForFront->push_front(nullptr);
    int32_t curUserId = 100;
    g_AVSessionService->GetUsersManager().frontSessionListMapByUserId_.clear();
    g_AVSessionService->GetUsersManager().frontSessionListMapByUserId_[curUserId] = sessionListForFront;
    std::vector<AVSessionDescriptor> descriptors;
    g_AVSessionService->GetAllSessionDescriptors(descriptors);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_EQ(descriptors.size(), 1);
}

/**
 * @tc.name: GetSessionDescriptorsBySessionId001
 * @tc.desc: Test GetSessionDescriptorsBySessionId when normal branch
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, GetSessionDescriptorsBySessionId001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    std::string sessionId = avsessionHere->GetSessionId();
    AVSessionDescriptor descriptor;
    int32_t ret = g_AVSessionService->GetSessionDescriptorsBySessionId(sessionId, descriptor);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ProcessDescriptorsFromCJSON001
 * @tc.desc: Test ProcessDescriptorsFromCJSON when valueItem without sessionId
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ProcessDescriptorsFromCJSON001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    std::string sessionInfoStr = R"({})";
    cJSON* valueItem = cJSON_Parse(sessionInfoStr.c_str());
    std::vector<AVSessionDescriptor> descriptors;
    g_AVSessionService->ProcessDescriptorsFromCJSON(descriptors, valueItem);
    EXPECT_EQ(0, descriptors.size());
}

/**
 * @tc.name: ProcessDescriptorsFromCJSON002
 * @tc.desc: Test ProcessDescriptorsFromCJSON when valueItem without bundleName
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ProcessDescriptorsFromCJSON002, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    std::string sessionInfoStr = R"({
        "sessionId": "123"
    })";
    cJSON* valueItem = cJSON_Parse(sessionInfoStr.c_str());
    std::vector<AVSessionDescriptor> descriptors;
    g_AVSessionService->ProcessDescriptorsFromCJSON(descriptors, valueItem);
    EXPECT_EQ(0, descriptors.size());
}

/**
 * @tc.name: ProcessDescriptorsFromCJSON003
 * @tc.desc: Test ProcessDescriptorsFromCJSON when valueItem without abilityName
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ProcessDescriptorsFromCJSON003, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    std::string sessionInfoStr = R"({
        "sessionId": "123",
        "bundleName": "bundleName_test"
    })";
    cJSON* valueItem = cJSON_Parse(sessionInfoStr.c_str());
    std::vector<AVSessionDescriptor> descriptors;
    g_AVSessionService->ProcessDescriptorsFromCJSON(descriptors, valueItem);
    EXPECT_EQ(0, descriptors.size());
}

/**
 * @tc.name: ProcessDescriptorsFromCJSON004
 * @tc.desc: Test ProcessDescriptorsFromCJSON when valueItem without sessionTag
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ProcessDescriptorsFromCJSON004, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    std::string sessionInfoStr = R"({
        "sessionId": "123",
        "bundleName": "bundleName_test",
        "abilityName": "abilityName_test",
        "sessionTag": "testTag"
    })";
    cJSON* valueItem = cJSON_Parse(sessionInfoStr.c_str());
    std::vector<AVSessionDescriptor> descriptors;
    g_AVSessionService->ProcessDescriptorsFromCJSON(descriptors, valueItem);
    EXPECT_EQ(1, descriptors.size());
}

/**
 * @tc.name: CheckSessionHandleKeyEvent001
 * @tc.desc: Test CheckSessionHandleKeyEvent when ancoSession_ is not nullptr
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, CheckSessionHandleKeyEvent001, TestSize.Level0)
{
    bool procCmd = true;
    AVControlCommand cmd;
    auto keyEvent = MMI::KeyEvent::Create();
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> session = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(session != nullptr);
    g_AVSessionService->ancoSession_ = nullptr;
    bool ret = g_AVSessionService->CheckSessionHandleKeyEvent(procCmd, cmd, *keyEvent, session);

    g_AVSessionService->ancoSession_ = session;
    g_AVSessionService->ancoSession_->Activate();
    ret = g_AVSessionService->CheckSessionHandleKeyEvent(procCmd, cmd, *keyEvent, session);

    g_AVSessionService->ancoSession_->Deactivate();
    ret = g_AVSessionService->CheckSessionHandleKeyEvent(procCmd, cmd, *keyEvent, session);
    g_AVSessionService->HandleSessionRelease(session->GetSessionId());
    session->Destroy();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: HandleSystemKeyColdStart001
 * @tc.desc: Verfying HandleSystemKeyColdStart when IsAncoValid() is true
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, HandleSystemKeyColdStart001, TestSize.Level0)
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testAnotherBundleName);
    elementName.SetAbilityName(g_testAnotherAbilityName);
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::sptr<AVSessionItem> avsessionHere = g_AVSessionService->CreateSessionInner(
        g_testSessionTag, AVSession::SESSION_TYPE_VOICE_CALL, false, elementName);
    CHECK_AND_RETURN(avsessionHere != nullptr);
    g_AVSessionService->GetUsersManager().frontSessionListMapByUserId_.clear();
    g_AVSessionService->ancoSession_ = avsessionHere;
    g_AVSessionService->ancoSession_->Activate();
    AVControlCommand command;
    command.SetCommand(AVControlCommand::SESSION_CMD_INVALID);
    g_AVSessionService->HandleSystemKeyColdStart(command);
    EXPECT_EQ(avsessionHere->remoteSink_, nullptr);
    g_AVSessionService->HandleSessionRelease(avsessionHere->GetSessionId());
    avsessionHere->Destroy();
}

/**
 * @tc.name: OnClientDied001
 * @tc.desc: Verfying OnClientDied when BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid) == ""
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, OnClientDied001, TestSize.Level0)
{
    pid_t pid = 1000;
    pid_t uid = 1001;
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->OnClientDied(pid, uid);
    EXPECT_TRUE(g_AVSessionService->cacheEnableCastPids_.empty());
}

/**
 * @tc.name: ClearControllerForClientDiedNoLock001
 * @tc.desc: Verfying ClearControllerForClientDiedNoLock when controllers.empty() == true
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ClearControllerForClientDiedNoLock001, TestSize.Level0)
{
    pid_t pid = 1000;
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->controllers_.clear();
    g_AVSessionService->ClearControllerForClientDiedNoLock(pid);
    EXPECT_TRUE(g_AVSessionService->controllers_.empty());
}

/**
 * @tc.name: SuperLauncher001
 * @tc.desc: Verifying SuperLauncher with invalid state
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, SuperLauncher001, TestSize.Level0)
{
    std::string deviceId = "test_deviceId";
    std::string serviceName = "SuperLauncher-Dual";
    std::string extraInfo = "";
    const std::string state = "test_state";
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->SuperLauncher(deviceId, serviceName, extraInfo, state);
    EXPECT_EQ(g_AVSessionService->migrateAVSession_, nullptr);
}

/**
 * @tc.name: ReleaseSuperLauncher001
 * @tc.desc: Test ReleaseSuperLauncher with migrateAVSession_ is nullptr
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ReleaseSuperLauncher001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->migrateAVSession_.reset();
    g_AVSessionService->ReleaseSuperLauncher("SuperLauncher-Dual");
    EXPECT_EQ(g_AVSessionService->migrateAVSession_, nullptr);
}

/**
 * @tc.name: RemoveHistoricalRecordListener001
 * @tc.desc: Test RemoveHistoricalRecordListener with normal branch
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, RemoveHistoricalRecordListener001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    TestHistoricalRecordListener* listener1 = new TestHistoricalRecordListener();
    CHECK_AND_RETURN(listener1 != nullptr);
    TestHistoricalRecordListener* listener2 = new TestHistoricalRecordListener();
    CHECK_AND_RETURN(listener2 != nullptr);
    g_AVSessionService->AddHistoricalRecordListener(listener1);
    g_AVSessionService->AddHistoricalRecordListener(listener2);
    g_AVSessionService->AddHistoricalRecordListener(nullptr);
    const std::string bundleName = "test_bundle";
    int32_t userId = 1001;
    g_AVSessionService->NotifyHistoricalRecordChange(bundleName, userId);
    g_AVSessionService->RemoveHistoricalRecordListener(listener1);
    EXPECT_EQ(g_AVSessionService->historicalRecordListeners_.size(), 2);
    g_AVSessionService->RemoveHistoricalRecordListener(listener2);
    EXPECT_EQ(g_AVSessionService->historicalRecordListeners_.size(), 1);
    delete listener1;
    delete listener2;
}

/**
 * @tc.name: NotifyDeviceStateChange001
 * @tc.desc: Test NotifyDeviceStateChange with normal branch
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, NotifyDeviceStateChange001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    pid_t pid = 1001;
    sptr<ISessionListener> listener = new TestISessionListener();
    CHECK_AND_RETURN(listener != nullptr);
    g_AVSessionService->GetUsersManager().AddSessionListener(pid, listener);
    DeviceState deviceState;
    g_AVSessionService->NotifyDeviceStateChange(deviceState);
    g_AVSessionService->GetUsersManager().AddSessionListener(pid, nullptr);
    g_AVSessionService->NotifyDeviceStateChange(deviceState);
    EXPECT_TRUE(g_isCallOnTopSessionChange);
}

/**
 * @tc.name: ReportStartCastEnd001
 * @tc.desc: Test ReportStartCastEnd with ret is AVSESSION_SUCCESS
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ReportStartCastEnd001, TestSize.Level0)
{
    std::string func = "test_func";
    OutputDeviceInfo outputDeviceInfo;
    int32_t uid = 1001;
    int ret = AVSESSION_SUCCESS;
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->ReportStartCastEnd(func, outputDeviceInfo, uid, ret);
    EXPECT_EQ(outputDeviceInfo.deviceInfos_.size(), 0);
}

/**
 * @tc.name: ProcessTargetMigrate001
 * @tc.desc: Test ProcessTargetMigrate localDeviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, ProcessTargetMigrate001, TestSize.Level0)
{
#ifdef DEVICE_MANAGER_ENABLE
    bool isOnline = true;
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    deviceInfo.deviceTypeId = OHOS::DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    deviceInfo.extraData = R"({"OS_TYPE": 1})";
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->localDeviceType_ = DistributedHardware::DmDeviceType::DEVICE_TYPE_TV;
    bool ret = g_AVSessionService->ProcessTargetMigrate(isOnline, deviceInfo);
    EXPECT_TRUE(ret);
#endif
}

/**
 * @tc.name: DoConnectProcessWithMigrateServer001
 * @tc.desc: Test DoConnectProcessWithMigrateServer migrateAVSessionServerMap_.find(networkId) !=
 *           migrateAVSessionServerMap_.end()
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, DoConnectProcessWithMigrateServer001, TestSize.Level0)
{
#ifdef DEVICE_MANAGER_ENABLE
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    std::string networkId = "test_networkId";
    strncpy_s(deviceInfo.networkId, sizeof(deviceInfo.networkId), networkId.c_str(), networkId.length());
    std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer = std::make_shared<MigrateAVSessionServer>();
    CHECK_AND_RETURN(migrateAVSessionServer != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_[networkId] = migrateAVSessionServer;
    g_AVSessionService->DoConnectProcessWithMigrateServer(deviceInfo);
    EXPECT_FALSE(g_AVSessionService->migrateAVSessionServerMap_.empty());
#endif
}

/**
 * @tc.name: DoDisconnectProcessWithMigrateServer001
 * @tc.desc: Test DoDisconnectProcessWithMigrateServer migrateAVSessionServer != nullptr
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, DoDisconnectProcessWithMigrateServer001, TestSize.Level0)
{
#ifdef DEVICE_MANAGER_ENABLE
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    std::string networkId = "test_networkId";
    strncpy_s(deviceInfo.networkId, sizeof(deviceInfo.networkId), networkId.c_str(), networkId.length());
    std::shared_ptr<MigrateAVSessionServer> migrateAVSessionServer = std::make_shared<MigrateAVSessionServer>();
    CHECK_AND_RETURN(migrateAVSessionServer != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_[networkId] = migrateAVSessionServer;
    g_AVSessionService->DoDisconnectProcessWithMigrateServer(deviceInfo);
    EXPECT_TRUE(g_AVSessionService->migrateAVSessionServerMap_.empty());
#endif
}

/**
 * @tc.name: NotifyLocalFrontSessionChangeForMigrate001
 * @tc.desc: Cover if (localFrontSessionId_.empty() && localFrontSessionIdUpdate.length() > 0)
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, NotifyLocalFrontSessionChangeForMigrate001, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("OLD_00");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_00", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_00") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("SAME_01");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_01", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_01") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("SAME_01");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "SAME_01");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_10", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_10") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_11", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_if1_11") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("ARRIVE_11");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "ARRIVE_11");
}

/**
 * @tc.name: NotifyLocalFrontSessionChangeForMigrate002
 * @tc.desc: Cover if (!localFrontSessionId_.empty() && localFrontSessionIdUpdate.length() > 0
 *           && localFrontSessionId_ != localFrontSessionIdUpdate)
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, NotifyLocalFrontSessionChangeForMigrate002, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_000", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_000") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_001", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_001") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_010", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_010") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("010");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "010");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_011", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_011") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("011");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "011");
}

/**
 * @tc.name: NotifyLocalFrontSessionChangeForMigrate003
 * @tc.desc: Cover if (!localFrontSessionId_.empty() && localFrontSessionIdUpdate.length() > 0
 *           && localFrontSessionId_ != localFrontSessionIdUpdate)
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, NotifyLocalFrontSessionChangeForMigrate003, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("OLD_100");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_100", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_100") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("OLD_101");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_101", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_101") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("SAME_110");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_110", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_110") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("SAME_110");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "SAME_110");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("OLD_111");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_111", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_111") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("NEW_111");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "NEW_111");
}

/**
 * @tc.name: NotifyLocalFrontSessionChangeForMigrate004
 * @tc.desc: Cover if (!localFrontSessionId_.empty() && localFrontSessionIdUpdate.empty())
 * @tc.type: FUNC
 * @tc.require: #I5Y4MZ
 */
static HWTEST_F(AVSessionServiceTestExt, NotifyLocalFrontSessionChangeForMigrate004, TestSize.Level0)
{
    CHECK_AND_RETURN(g_AVSessionService != nullptr);
    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_00", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_00") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("00");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "00");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_01", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_01") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("KEEP_10");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_10", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_10") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("10");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "10");

    g_AVSessionService->migrateAVSessionServerMap_.clear();
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("TO_LEAVE_11");
    g_AVSessionService->migrateAVSessionServerMap_.insert(
        { "nid_11", std::make_shared<MigrateAVSessionServer>(MIGRATE_MODE_NEXT, "nid_11") });
    g_AVSessionService->NotifyLocalFrontSessionChangeForMigrate("");
    EXPECT_EQ(g_AVSessionService->localFrontSessionId_, "");
}
} // AVSession
} // OHOS