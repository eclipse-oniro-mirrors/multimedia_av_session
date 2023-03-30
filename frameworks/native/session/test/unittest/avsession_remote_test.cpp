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

#include <gtest/gtest.h>

#include "avsession_manager.h"
#include "avsession_info.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "softbus_bus_center.h"
#include "avsession_log.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include "device_manager_callback.h"
#include "audio_system_manager.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"


using namespace testing::ext;
using namespace OHOS::AudioStandard;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {
const int32_t DECICE_ID = 2;

static HapInfoParams g_info = {
    .userID = 100,
    .bundleName = "ohos.permission_test.demo",
    .instIndex = 0,
    .appIDDesc = "ohos.permission_test.demo",
    .isSystemApp = true
};

static HapPolicyParams g_policy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .bundleName = "ohos.permission_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.MANAGE_MEDIA_RESOURCES",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};
static uint64_t g_selfTokenId = 0;
static int32_t g_onCall = AVSESSION_ERROR;
static char g_testSessionTag[] = "test";
static char g_testBundleName[] = "test.ohos.avsession";
static char g_testAbilityName[] = "test.ability";
static std::vector<AudioDeviceDescriptor> g_descriptors;

class InitCallback : public OHOS::DistributedHardware::DmInitCallback {
public:
    ~InitCallback() override
    {
    }
    void OnRemoteDied() override
    {
    }
};

class AVSessionRemoteTest : public testing::Test {
public:
    static constexpr char testPkgName[] = "av_session";
    static constexpr int nodeNumber = 4;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<AVSession> avsession_ = nullptr;
};

void AVSessionRemoteTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);

    NodeBasicInfo *nodeInfo[nodeNumber];
    int32_t infoNum = nodeNumber;
    GetAllNodeDeviceInfo(testPkgName, nodeInfo, &infoNum);
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList;
    auto callback = std::make_shared<InitCallback>();
    int ret = OHOS::DistributedHardware::DeviceManager::GetInstance().InitDeviceManager("av_session", callback);
    SLOGI("InitDeviceManager ret is %{public}d", ret);
    ret = OHOS::DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList("av_session", "", deviceList);
    SLOGI("GetTrustedDeviceList ret is %{public}d", ret);
    SLOGI("GetTrustedDeviceList size is %{public}d", static_cast<int32_t>(deviceList.size()));
    ASSERT_NE(infoNum, 0);
    AudioDeviceDescriptor descriptor;
    for (int32_t i = 0; i < deviceList.size(); i++) {
        descriptor.networkId_ = deviceList[i].networkId;
        descriptor.deviceId_ = DECICE_ID;
        g_descriptors.push_back(descriptor);
        SLOGI("g_sinkDevices is %{public}s", deviceList[i].networkId);
    }
}

void AVSessionRemoteTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVSessionRemoteTest::SetUp()
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(g_testBundleName);
    elementName.SetAbilityName(g_testAbilityName);
    avsession_ =
        AVSessionManager::GetInstance().CreateSession(g_testSessionTag, AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(avsession_, nullptr);
}

void AVSessionRemoteTest::TearDown()
{
    [[maybe_unused]] int32_t ret = AVSESSION_ERROR;
    if (avsession_ != nullptr) {
        ret = avsession_->Destroy();
        avsession_ = nullptr;
    }
}

class AVSessionCastAudioCallbackImpl : public AVSessionCallback {
public:
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent) override;
    void OnOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo) override;
    void OnCommonCommand(const std::string& commonCommand, const OHOS::AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override;

    ~AVSessionCastAudioCallbackImpl() override;
};

void AVSessionCastAudioCallbackImpl::OnPlay()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlay %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnPause()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPause %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnStop()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnStop %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnPlayNext()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayNext %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnPlayPrevious()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnPlayPrevious %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnFastForward()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnFastForward %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnRewind()
{
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnRewind %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnSeek(int64_t time)
{
    SLOGE("OnSeek %{public}" PRId64, time);
    g_onCall = AVSESSION_SUCCESS;
}
void AVSessionCastAudioCallbackImpl::OnSetSpeed(double speed)
{
    SLOGE("OnSetSpeed %{public}f", speed);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetSpeed %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnSetLoopMode(int32_t loopMode)
{
    SLOGE("OnSetLoopMode %{public}d", loopMode);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetLoopMode %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnToggleFavorite(const std::string& mediald)
{
    SLOGE("OnToggleFavorite %{public}s", mediald.c_str());
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnToggleFavorite %{public}d", g_onCall);
}
void AVSessionCastAudioCallbackImpl::OnMediaKeyEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    SLOGE("OnMediaKeyEvent");
    g_onCall = AVSESSION_SUCCESS;
}
void AVSessionCastAudioCallbackImpl::OnOutputDeviceChange(const OutputDeviceInfo& info)
{
    SLOGE("OnOutputDeviceChange");
    g_onCall = AVSESSION_SUCCESS;
}
void AVSessionCastAudioCallbackImpl::OnCommonCommand(const std::string& commonCommand,
    const OHOS::AAFwk::WantParams& commandArgs)
{
    SLOGI("OnCommonCommand");
    g_onCall = AVSESSION_SUCCESS;
}
void AVSessionCastAudioCallbackImpl::OnSkipToQueueItem(int32_t itemId)
{
    SLOGE("OnSkipToQueueItem %{public}d", itemId);
    g_onCall = AVSESSION_SUCCESS;
    SLOGE("OnSetSpeed %{public}d", g_onCall);
}
AVSessionCastAudioCallbackImpl::~AVSessionCastAudioCallbackImpl()
{
}

/**
* @tc.name: CastAudio001
* @tc.desc: Cast current audio to the remote device
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudio001, TestSize.Level1)
{
    SLOGE("CastAudio001 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    EXPECT_NE(AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors), AVSESSION_SUCCESS);
    SLOGE("CastAudio001 End");
}

/**
* @tc.name: CastAudio002
* @tc.desc: Invalid params for sessionToken
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudio002, TestSize.Level1)
{
    SLOGE("CastAudio002 Begin");
    SessionToken sessionToken;
    EXPECT_EQ(AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors), ERR_INVALID_PARAM);
    SLOGE("CastAudio002 End");
}

/**
* @tc.name: CastAudio003
* @tc.desc: Invalid params for sessionToken
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudio003, TestSize.Level1)
{
    SLOGE("CastAudio003 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = "123456789";
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    EXPECT_EQ(AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors), ERR_INVALID_PARAM);
    SLOGE("CastAudio003 End");
}

/**
* @tc.name: CastAudio004
* @tc.desc: Invalid params for descriptors
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudio004, TestSize.Level1)
{
    SLOGE("CastAudio004 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    std::vector<AudioDeviceDescriptor> descriptors;
    EXPECT_EQ(AVSessionManager::GetInstance().CastAudio(sessionToken, descriptors), ERR_INVALID_PARAM);
    SLOGE("CastAudio004 End");
}

/**
* @tc.name: CastAudioForAll001
* @tc.desc: Cast current all audios to the remote device
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudioForAll001, TestSize.Level1)
{
    SLOGE("CastAudioForAll001 Begin");
    EXPECT_NE(AVSessionManager::GetInstance().CastAudioForAll(g_descriptors), AVSESSION_SUCCESS);
    SLOGE("CastAudioForAll001 End");
}

/**
* @tc.name: CastAudioForAll002
* @tc.desc: Invalid params for descriptors
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, CastAudioForAll002, TestSize.Level1)
{
    SLOGE("CastAudioForAll002 Begin");
    std::vector<AudioDeviceDescriptor> descriptors;
    EXPECT_EQ(AVSessionManager::GetInstance().CastAudioForAll(descriptors), ERR_INVALID_PARAM);
    SLOGE("CastAudioForAll002 End");
}

/**
* @tc.name: SetAVMetaData001
* @tc.desc: Set av meta data to remote devices
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, SetAVMetaData001, TestSize.Level1)
{
    SLOGE("SetAVMetaData001 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors);
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("123");
    metaData.SetTitle("Black Humor");
    metaData.SetArtist("zhoujielun");
    metaData.SetAuthor("zhoujielun");
    metaData.SetAlbum("Jay");
    metaData.SetWriter("zhoujielun");
    metaData.SetComposer("zhoujielun");
    metaData.SetDuration(40000);
    metaData.SetMediaImageUri("xxxxx");
    metaData.SetSubTitle("fac");
    metaData.SetDescription("for friends");
    metaData.SetLyric("xxxxx");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    SLOGE("SetAVMetaData001 End");
}


/**
* @tc.name: SetAVPlaybackState001
* @tc.desc: Set av playback state to remote devices
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, SetAVPlaybackState001, TestSize.Level1)
{
    SLOGE("SetAVPlaybackState001 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors);
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("playback");
    metaData.SetDuration(2000000);
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    AVPlaybackState playbackState;
    playbackState.SetState(1);
    playbackState.SetSpeed(1);
    playbackState.SetPosition({80000, 0});
    playbackState.SetBufferedTime(700000);
    playbackState.SetLoopMode(1);
    playbackState.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(playbackState), AVSESSION_SUCCESS);
    SLOGE("SetAVPlaybackState001 End");
}

/**
* @tc.name: SendControlCommand001
* @tc.desc: Send control command by remote controller to local device
* @tc.type: FUNC
* @tc.require: AR000H55F5
*/
HWTEST_F(AVSessionRemoteTest, SendControlCommand001, TestSize.Level1)
{
    SLOGE("SendControlCommand001 Begin");
    std::shared_ptr<AVSessionController> controller;
    auto ret = AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller);
    ASSERT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(controller, nullptr);
    sleep(1);
    EXPECT_EQ(avsession_->Activate(), AVSESSION_SUCCESS);
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors);
    std::shared_ptr<AVSessionCallback> callback = std::make_shared<AVSessionCastAudioCallbackImpl>();
    EXPECT_EQ(avsession_->RegisterCallback(callback), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    AVControlCommand cmd;
    EXPECT_EQ(cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    EXPECT_EQ(controller->SendControlCommand(cmd), AVSESSION_SUCCESS);
    if (controller != nullptr) {
        ret = controller->Destroy();
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
        controller = nullptr;
        EXPECT_EQ(controller, nullptr);
    }
    SLOGE("SendControlCommand001 End");
}

/**
* @tc.name: GetController001
* @tc.desc: Get controller by session
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetController001, TestSize.Level1)
{
    SLOGE("GetController001 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors);

    auto controller = avsession_->GetController();
    ASSERT_NE(controller, nullptr);
    SLOGE("GetController001 End");
}

/**
* @tc.name: GetController002
* @tc.desc: The controller fetched twice through session is same
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetController002, TestSize.Level1)
{
    SLOGE("GetController002 Begin");
    SessionToken sessionToken;
    sessionToken.sessionId = avsession_->GetSessionId();
    sessionToken.pid = 111;
    sessionToken.uid = 2222;
    AVSessionManager::GetInstance().CastAudio(sessionToken, g_descriptors);

    auto controller = avsession_->GetController();
    auto controller1 = avsession_->GetController();
    ASSERT_NE(controller, nullptr);
    ASSERT_NE(controller1, nullptr);
    EXPECT_EQ(controller->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller1->Destroy(), ERR_CONTROLLER_NOT_EXIST);
    SLOGE("GetController002 End");
}

/**
* @tc.name: GetOutputDevice001
* @tc.desc: Get output device information by session
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetOutputDevice001, TestSize.Level1)
{
    SLOGE("GetOutputDevice001 Begin");
    AVSessionDescriptor descriptor;
    auto ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(avsession_->GetSessionId(), descriptor);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGE("avsession get deviceIds_ size %{public}d",
          static_cast<int32_t>(descriptor.outputDeviceInfo_.deviceIds_.size()));
    SLOGE("avsession get deviceId0 %{public}s", descriptor.outputDeviceInfo_.deviceIds_[0].c_str());
    ASSERT_NE(descriptor.outputDeviceInfo_.deviceIds_.size(), 0);
    SLOGE("avsession get deviceNames_ size %{public}d",
          static_cast<int32_t>(descriptor.outputDeviceInfo_.deviceNames_.size()));
    SLOGE("avsession get deviceName0 %{public}s", descriptor.outputDeviceInfo_.deviceNames_[0].c_str());
    ASSERT_NE(descriptor.outputDeviceInfo_.deviceNames_.size(), 0);
    SLOGE("GetOutputDevice001 End");
}

/**
* @tc.name: GetOutputDevice002
* @tc.desc: Invalid params for sessionId
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetOutputDevice002, TestSize.Level1)
{
    SLOGE("GetOutputDevice002 Begin");
    AVSessionDescriptor descriptor;
    EXPECT_EQ(AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId("123456789", descriptor),
              AVSESSION_ERROR);
    SLOGE("GetOutputDevice002 End");
}

/**
* @tc.name: GetOutputDevice003
* @tc.desc: Invalid params for sessionId
* @tc.type: FUNC
* @tc.require: AR000H55FQ
*/
HWTEST_F(AVSessionRemoteTest, GetOutputDevice003, TestSize.Level1)
{
    SLOGE("GetOutputDevice003 Begin");
    AVSessionDescriptor descriptor;
    EXPECT_EQ(AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId("", descriptor), ERR_INVALID_PARAM);
    SLOGE("GetOutputDevice003 End");
}

/**
* @tc.name: GetOutputDevice004
* @tc.desc: Get output device information by controller
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetOutputDevice004, TestSize.Level1)
{
    SLOGE("GetOutputDevice004 Begin");
    std::shared_ptr<AVSessionController> controller = nullptr;
    auto ret = AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(controller, nullptr);

    AVSessionDescriptor descriptor;
    ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(controller->GetSessionId(), descriptor);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGE("controller get deviceIds_ size %{public}d",
          static_cast<int32_t>(descriptor.outputDeviceInfo_.deviceIds_.size()));
    SLOGE("controller get deviceId0 %{public}s", descriptor.outputDeviceInfo_.deviceIds_[0].c_str());
    ASSERT_NE(descriptor.outputDeviceInfo_.deviceIds_.size(), 0);
    SLOGE("controller get deviceNames_ size %{public}d",
          static_cast<int32_t>(descriptor.outputDeviceInfo_.deviceNames_.size()));
    SLOGE("controller get deviceName0 %{public}s", descriptor.outputDeviceInfo_.deviceNames_[0].c_str());
    ASSERT_NE(descriptor.outputDeviceInfo_.deviceNames_.size(), 0);
    if (controller != nullptr) {
    ret = controller->Destroy();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    controller = nullptr;
    EXPECT_EQ(controller, nullptr);
    }
    SLOGE("GetOutputDevice004 End");
}

/**
* @tc.name: GetOutputDevice005
* @tc.desc: Get same output device information by controller and session
* @tc.type: FUNC
* @tc.require: AR000H55F4
*/
HWTEST_F(AVSessionRemoteTest, GetOutputDevice005, TestSize.Level1)
{
    SLOGE("GetOutputDevice005 Begin");
    AVSessionDescriptor descriptor1;
    auto ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(avsession_->GetSessionId(),
                                                                                descriptor1);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(descriptor1.outputDeviceInfo_.deviceIds_.size(), 0);
    ASSERT_NE(descriptor1.outputDeviceInfo_.deviceNames_.size(), 0);

    std::shared_ptr<AVSessionController> controller = nullptr;
    ret = AVSessionManager::GetInstance().CreateController(avsession_->GetSessionId(), controller);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(controller, nullptr);

    AVSessionDescriptor descriptor2;
    ret = AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(controller->GetSessionId(), descriptor2);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    ASSERT_NE(descriptor2.outputDeviceInfo_.deviceIds_.size(), 0);
    ASSERT_NE(descriptor2.outputDeviceInfo_.deviceNames_.size(), 0);

    EXPECT_EQ(descriptor1.outputDeviceInfo_.deviceIds_.size(), descriptor2.outputDeviceInfo_.deviceIds_.size());
    EXPECT_EQ(descriptor1.outputDeviceInfo_.deviceIds_[0], descriptor2.outputDeviceInfo_.deviceIds_[0]);
    EXPECT_EQ(descriptor1.outputDeviceInfo_.deviceNames_.size(), descriptor2.outputDeviceInfo_.deviceNames_.size());
    EXPECT_EQ(descriptor1.outputDeviceInfo_.deviceNames_[0], descriptor2.outputDeviceInfo_.deviceNames_[0]);
    if (controller != nullptr) {
        ret = controller->Destroy();
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
        controller = nullptr;
    }
    SLOGE("GetOutputDevice005 End");
}
} // namespace AVSession
} // namespace OHOS
