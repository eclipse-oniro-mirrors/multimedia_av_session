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

#include "avsession_errors.h"
#include "avsession_manager.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

constexpr uint64_t TestMicroSecond = 1000;

class AVSessionControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<AVSession> avsession_ = nullptr;
    std::shared_ptr<AVSessionController> controller_ = nullptr;
};

void AVSessionControllerTest::SetUpTestCase()
{
}

void AVSessionControllerTest::TearDownTestCase()
{
}

void AVSessionControllerTest::SetUp()
{
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName("demo");
    elementName.SetAbilityName("demo");
    avsession_ = AVSessionManager::CreateSession("Application", AVSession::SESSION_TYPE_AUDIO, elementName);
    ASSERT_NE(avsession_, nullptr);

    controller_ = AVSessionManager::CreateController(avsession_->GetSessionId());
    ASSERT_NE(controller_, nullptr);
}

void AVSessionControllerTest::TearDown()
{
    auto ret = avsession_->Destroy();
    ASSERT_EQ(AVSESSION_SUCCESS, ret);
    controller_->Release();
    ASSERT_EQ(AVSESSION_SUCCESS, ret);
}

class AVControllerCallbackImpl : public AVControllerCallback {
public:
    void OnSessionDestroy() override;

    void OnPlaybackStateChange(const AVPlaybackState &state) override;

    void OnMetaDataChange(const AVMetaData &data) override;

    void OnActiveStateChange(bool isActive) override;

    void OnValidCommandChange(const std::vector<int32_t> &cmds) override;

    ~AVControllerCallbackImpl() override;

    bool isActive_ = false;
    AVMetaData data_;
    AVPlaybackState state_;
    bool isDestory_ = false;
    std::vector<int32_t> cmds_;
};

AVControllerCallbackImpl::~AVControllerCallbackImpl()
{
}

void AVControllerCallbackImpl::OnSessionDestroy()
{
    isDestory_ = true;
}

void AVControllerCallbackImpl::OnPlaybackStateChange(const AVPlaybackState &state)
{
    state_ = state;
}

void AVControllerCallbackImpl::OnMetaDataChange(const AVMetaData &data)
{
    data_ = data;
}

void AVControllerCallbackImpl::OnActiveStateChange(bool isActive)
{
    isActive_ = isActive;
}

void AVControllerCallbackImpl::OnValidCommandChange(const std::vector<int32_t> &cmds)
{
    cmds_ = cmds;
}

bool IsAVPlaybackStateEqual(AVPlaybackState& state1,  AVPlaybackState& state2)
{
    return state1.GetState() == state2.GetState() &&
        std::fabs(state1.GetSpeed() - state2.GetSpeed()) < 1e-6 &&
        state1.GetPosistion().elapsedTime_ == state2.GetPosistion().elapsedTime_ &&
        state1.GetBufferedTime() == state2.GetBufferedTime() &&
        state1.GetLoopMode() == state2.GetLoopMode() &&
        state1.GetFavorite() == state2.GetFavorite();
}

/**
* @tc.name: IsSessionActive001
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, IsSessionActive001, TestSize.Level1)
{
    bool active = true;
    EXPECT_EQ(controller_->IsSessionActive(active), AVSESSION_SUCCESS);
    EXPECT_EQ(active, false);
    EXPECT_EQ(avsession_->Activate(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->IsSessionActive(active), AVSESSION_SUCCESS);
    EXPECT_EQ(active, true);
}

/**
* @tc.name: IsSessionActive002
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, IsSessionActive002, TestSize.Level1)
{
    bool active = true;
    EXPECT_EQ(avsession_->Deactivate(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->IsSessionActive(active), AVSESSION_SUCCESS);
    EXPECT_EQ(active, false);
}

/**
* @tc.name: IsSessionActive003
* @tc.desc: Return is Session Actived
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, IsSessionActive003, TestSize.Level1)
{
    bool active = false;
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->IsSessionActive(active), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: GetAVPlaybackState001
* @tc.desc: Return AVPlaybackState
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetAVPlaybackState001, TestSize.Level1)
{
    AVPlaybackState state;
    state.SetState(1);
    state.SetSpeed(1);
    state.SetBufferedTime(1);
    state.SetPosition({ 1, 0 });
    state.SetLoopMode(1);
    state.SetFavorite(true);
    EXPECT_EQ(avsession_->SetAVPlaybackState(state), AVSESSION_SUCCESS);
    AVPlaybackState resultState;
    EXPECT_EQ(controller_->GetAVPlaybackState(resultState), AVSESSION_SUCCESS);
    EXPECT_EQ(IsAVPlaybackStateEqual(state, resultState), true);
}

/**
* @tc.name: GetAVPlaybackState002
* @tc.desc: Return AVPlaybackState
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetAVPlaybackState002, TestSize.Level1)
{
    AVPlaybackState state;
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetAVPlaybackState(state), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: GetAVMetaData001
* @tc.desc: Return AVMetaData
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetAVMetaData001, TestSize.Level1)
{
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("001");
    metaData.SetTitle("123456");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);
    AVMetaData resultMetaData;
    resultMetaData.Reset();
    EXPECT_EQ(controller_->GetAVMetaData(resultMetaData), AVSESSION_SUCCESS);
    EXPECT_EQ(resultMetaData.GetAssetId(), "001");
    EXPECT_EQ(resultMetaData.GetTitle(), "123456");
}

/**
* @tc.name: GetAVMetaData002
* @tc.desc: Return AVMetaData
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetAVMetaData002, TestSize.Level1)
{
    AVMetaData metaData;
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetAVMetaData(metaData), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: SendMediaButtonEvent001
* @tc.desc: send System Media KeyEvent to system center
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, SendMediaButtonEvent001, TestSize.Level1)
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    item.SetDownTime(1);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    ASSERT_EQ(keyEvent->IsValid(), true);

    EXPECT_EQ(controller_->SendAVKeyEvent(*(keyEvent.get())), AVSESSION_SUCCESS);
}

/**
* @tc.name: SendMediaButtonEvent002
* @tc.desc: send System Media KeyEvent to system center
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, SendMediaButtonEvent002, TestSize.Level1)
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_EQ(keyEvent->IsValid(), false);

    EXPECT_EQ(controller_->SendAVKeyEvent(*(keyEvent.get())), ERR_INVALID_PARAM);
}

/**
* @tc.name: SendMediaButtonEvent003
* @tc.desc: send System Media KeyEvent to system center
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, SendMediaButtonEvent003, TestSize.Level1)
{
    auto keyEvent = OHOS::MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    item.SetDownTime(1);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    ASSERT_EQ(keyEvent->IsValid(), true);

    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->SendAVKeyEvent(*(keyEvent.get())), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: GetLaunchAbility001
* @tc.desc: get launch ability
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetLaunchAbility001, TestSize.Level1)
{
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    EXPECT_EQ(controller_->GetLaunchAbility(ability), AVSESSION_SUCCESS);
}

/**
* @tc.name: GetLaunchAbility002
* @tc.desc: get launch ability
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetLaunchAbility002, TestSize.Level1)
{
    OHOS::AbilityRuntime::WantAgent::WantAgent ability;
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetLaunchAbility(ability), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: GetValidCommands001
* @tc.desc: get supported command
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetValidCommands001, TestSize.Level1)
{
    std::vector<int32_t> cmds;
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PAUSE), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetValidCommands(cmds), AVSESSION_SUCCESS);
    std::vector<int32_t>::iterator it = std::find(cmds.begin(), cmds.end(), AVControlCommand::SESSION_CMD_PLAY);
    EXPECT_NE(it, cmds.end());
    it = std::find(cmds.begin(), cmds.end(), AVControlCommand::SESSION_CMD_PAUSE);
    EXPECT_NE(it, cmds.end());
    it = std::find(cmds.begin(), cmds.end(), AVControlCommand::SESSION_CMD_STOP);
    EXPECT_EQ(it, cmds.end());
}

/**
* @tc.name: GetValidCommands002
* @tc.desc: get supported command
* @tc.type: FUNC
* @tc.require: AR000H31JI
*/
HWTEST_F(AVSessionControllerTest, GetValidCommands002, TestSize.Level1)
{
    std::vector<int32_t> cmds;
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetValidCommands(cmds), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: SendControlCommand001
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand001, TestSize.Level1)
{
    AVControlCommand command;
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_INVALID), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_MAX), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SHUFFLE + 1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SEQUENCE - 1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetSpeed(-1), ERR_INVALID_PARAM);
    EXPECT_EQ(command.SetAssetId(""), ERR_INVALID_PARAM);
}

/**
* @tc.name: SendControlCommand002
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand002, TestSize.Level1)
{
    AVControlCommand command;
    int32_t mode = 0;
    double speed = 0.0;
    uint64_t time = 0;
    std::string assetId;
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_ERROR);
    EXPECT_EQ(command.GetSeekTime(time), AVSESSION_ERROR);
    EXPECT_EQ(command.GetAssetId(assetId), AVSESSION_ERROR);
    EXPECT_EQ(command.GetLoopMode(mode), AVSESSION_SUCCESS);
    EXPECT_EQ(mode, AVControlCommand::LOOP_MODE_SEQUENCE);
}

/**
* @tc.name: SendControlCommand003
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand003, TestSize.Level1)
{
    AVControlCommand command;
    int32_t mode = 0;
    double speed = 0.0;
    uint64_t time = 0;
    std::string assetId;
    EXPECT_EQ(command.SetAssetId("123456"), AVSESSION_SUCCESS);
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_ERROR);
    EXPECT_EQ(command.GetSeekTime(time), AVSESSION_ERROR);
    EXPECT_EQ(command.GetLoopMode(mode), AVSESSION_ERROR);
    EXPECT_EQ(command.GetAssetId(assetId), AVSESSION_SUCCESS);
    EXPECT_EQ(assetId, "123456");
}

/**
* @tc.name: SendControlCommand004
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand004, TestSize.Level1)
{
    AVControlCommand command;
    int32_t mode = 0;
    double speed = 0.0;
    uint64_t time = 0;
    std::string assetId;
    EXPECT_EQ(command.SetSpeed(1.0), AVSESSION_SUCCESS);
    EXPECT_EQ(command.GetSeekTime(time), AVSESSION_ERROR);
    EXPECT_EQ(command.GetAssetId(assetId), AVSESSION_ERROR);
    EXPECT_EQ(command.GetLoopMode(mode), AVSESSION_ERROR);
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_SUCCESS);
    EXPECT_EQ(std::fabs(speed - 1.0) < 1e-6, true);
}

/**
* @tc.name: SendControlCommand005
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand005, TestSize.Level1)
{
    AVControlCommand command;
    int32_t mode = 0;
    double speed = 0.0;
    uint64_t time = 0;
    std::string assetId;
    command.SetSeekTime(1);
    EXPECT_EQ(command.GetAssetId(assetId), AVSESSION_ERROR);
    EXPECT_EQ(command.GetLoopMode(mode), AVSESSION_ERROR);
    EXPECT_EQ(command.GetSpeed(speed), AVSESSION_ERROR);
    EXPECT_EQ(command.GetSeekTime(time), AVSESSION_SUCCESS);
    EXPECT_EQ(time, 1);
}

/**
* @tc.name: SendControlCommand006
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand006, TestSize.Level1)
{
    AVControlCommand command;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetAssetId("123456"), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), false);
}

/**
* @tc.name: SendControlCommand007
* @tc.desc: send command, check if AVControlCommand is invalid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand007, TestSize.Level1)
{
    AVControlCommand command;
    int32_t mode = -1;
    OHOS::Parcel parcel;
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.Marshalling(parcel), true);
    AVControlCommand *ret = AVControlCommand::Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->GetCommand(), AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    EXPECT_EQ(ret->GetLoopMode(mode), AVSESSION_SUCCESS);
    EXPECT_EQ(mode, AVControlCommand::LOOP_MODE_SEQUENCE);
    delete ret;
}

/**
* @tc.name: SendControlCommand008
* @tc.desc: send command, check if AVControlCommand is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand008, TestSize.Level1)
{
    AVControlCommand command;
    EXPECT_EQ(controller_->SendControlCommand(command), ERR_INVALID_PARAM);
}

/**
* @tc.name: SendControlCommand009
* @tc.desc: send command, check if AVControlCommand is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand009, TestSize.Level1)
{
    AVControlCommand command;
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->SendControlCommand(command), ERR_COMMAND_NOT_SUPPORT);
}

/**
* @tc.name: SendControlCommand010
* @tc.desc: send command, check if AVControlCommand is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand010, TestSize.Level1)
{
    AVControlCommand command;
    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_SET_LOOP_MODE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetLoopMode(AVControlCommand::LOOP_MODE_SEQUENCE), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->SendControlCommand(command), AVSESSION_SUCCESS);
}

/**
* @tc.name: SendControlCommand011
* @tc.desc: send command, check if AVControlCommand is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, SendControlCommand011, TestSize.Level1)
{
    AVControlCommand command;
    EXPECT_EQ(command.SetCommand(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE), AVSESSION_SUCCESS);
    EXPECT_EQ(command.SetAssetId("123456"), AVSESSION_SUCCESS);

    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->SendControlCommand(command), ERR_SESSION_NOT_EXIST);
}

/**
* @tc.name: RegisterCallback001
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback001, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
}

/**
* @tc.name: RegisterCallback002
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback002, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = nullptr;
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
}

/**
* @tc.name: RegisterCallback003
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback003, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    std::shared_ptr<AVControllerCallbackImpl> callbackNew = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_EQ(controller_->RegisterCallback(callbackNew), AVSESSION_SUCCESS);
}

/**
* @tc.name: RegisterCallback004
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback004, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);

    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    sleep(1);
    EXPECT_EQ(callback->isDestory_, true);
}

/**
* @tc.name: RegisterCallback005
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback005, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);

    EXPECT_EQ(avsession_->Activate(), AVSESSION_SUCCESS);
    sleep(1);
    EXPECT_EQ(callback->isActive_, true);
}

/**
* @tc.name: RegisterCallback006
* @tc.desc: register AVControllerCallback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, RegisterCallback006, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);

    EXPECT_EQ(avsession_->AddSupportCommand(AVControlCommand::SESSION_CMD_PLAY), AVSESSION_SUCCESS);
    sleep(1);
    std::vector<int32_t> cmds = callback->cmds_;
    std::vector<int32_t>::iterator it = std::find(cmds.begin(), cmds.end(), AVControlCommand::SESSION_CMD_PLAY);
    EXPECT_NE(it, cmds.end());
}

/**
* @tc.name: SetMetaFilter001
* @tc.desc: set meta filter,the func GetAVMetaData will return the item which is not in the meta filter
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, SetMetaFilter001, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    AVMetaData::MetaMaskType filter;
    filter.set(AVMetaData::META_KEY_TITLE);
    EXPECT_EQ(controller_->SetMetaFilter(filter), AVSESSION_SUCCESS);
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("001");
    metaData.SetTitle("123456");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);

    sleep(1);
    EXPECT_EQ(callback->data_.GetAssetId(), "");
    EXPECT_EQ(callback->data_.GetTitle(), "123456");
}

/**
* @tc.name: SetMetaFilter002
* @tc.desc: set meta filter,the func GetAVMetaData will return the item which is not in the meta filter
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, SetMetaFilter002, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    AVMetaData::MetaMaskType filter;
    EXPECT_EQ(controller_->SetMetaFilter(filter), AVSESSION_SUCCESS);
    AVMetaData metaData;
    metaData.Reset();
    metaData.SetAssetId("001");
    metaData.SetTitle("123456");
    EXPECT_EQ(avsession_->SetAVMetaData(metaData), AVSESSION_SUCCESS);

    sleep(1);
    EXPECT_EQ(callback->data_.GetAssetId(), "");
    EXPECT_EQ(callback->data_.GetTitle(), "");
}

/**
* @tc.name: SetPlaybackFilter001
* @tc.desc: set playback filter,the func GetAVPlaybackData will return the item which is not in the playback filter
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, SetPlaybackFilter001, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    AVPlaybackState::PlaybackStateMaskType filter;
    filter.set();
    EXPECT_EQ(controller_->SetPlaybackFilter(filter), AVSESSION_SUCCESS);
    AVPlaybackState state;
    state.SetLoopMode(AVControlCommand::LOOP_MODE_LIST);
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PREPARING);
    EXPECT_EQ(avsession_->SetAVPlaybackState(state), AVSESSION_SUCCESS);

    sleep(1);
    EXPECT_EQ(callback->state_.GetState(), AVPlaybackState::PLAYBACK_STATE_PREPARING);
    EXPECT_EQ(callback->state_.GetLoopMode(), AVControlCommand::LOOP_MODE_LIST);
}

/**
* @tc.name: SetPlaybackFilter002
* @tc.desc: set meta filter,the func GetAVPlaybackData will return the item which is not in the playback filter
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, SetPlaybackFilter002, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);
    AVPlaybackState::PlaybackStateMaskType filter;
    EXPECT_EQ(controller_->SetPlaybackFilter(filter), AVSESSION_SUCCESS);
    AVPlaybackState state;
    state.SetLoopMode(AVControlCommand::LOOP_MODE_LIST);
    state.SetState(AVPlaybackState::PLAYBACK_STATE_PREPARING);
    EXPECT_EQ(avsession_->SetAVPlaybackState(state), AVSESSION_SUCCESS);

    sleep(1);
    EXPECT_NE(callback->state_.GetState(), AVPlaybackState::PLAYBACK_STATE_PREPARING);
    EXPECT_NE(callback->state_.GetLoopMode(), AVControlCommand::LOOP_MODE_LIST);
}

/**
* @tc.name: GetSessionId001
* @tc.desc: Get SessionId bind with controller, check if GetSessionId is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, GetSessionId001, TestSize.Level1)
{
    int32_t id = controller_->GetSessionId();
    EXPECT_EQ(id >= 0, true);
    EXPECT_EQ(id, avsession_->GetSessionId());
}

/**
* @tc.name: GetSessionId002
* @tc.desc: Get SessionId bind with controller, check if GetSessionId is valid
* @tc.type: FUNC
* @tc.require: AR000H31JH
*/
HWTEST_F(AVSessionControllerTest, GetSessionId002, TestSize.Level1)
{
    EXPECT_EQ(avsession_->Destroy(), AVSESSION_SUCCESS);
    int32_t id = controller_->GetSessionId();
    EXPECT_EQ(id, AVSESSION_ERROR);
}

/**
* @tc.name: GetRealPlaybackPosition001
* @tc.desc: GetRealPlaybackPosition after recive callback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, GetRealPlaybackPosition001, TestSize.Level1)
{
    EXPECT_EQ(controller_->GetRealPlaybackPosition() , 0);
}

/**
* @tc.name: GetRealPlaybackPosition002
* @tc.desc: GetRealPlaybackPosition after recive callback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, GetRealPlaybackPosition002, TestSize.Level1)
{
    AVPlaybackState state;
    state.SetPosition({ TestMicroSecond * TestMicroSecond, TestMicroSecond });
    EXPECT_EQ(avsession_->SetAVPlaybackState(state), AVSESSION_SUCCESS);
    AVPlaybackState resultState;
    EXPECT_EQ(controller_->GetAVPlaybackState(resultState), AVSESSION_SUCCESS);
    EXPECT_EQ(controller_->GetRealPlaybackPosition() > 0, true);
}

/**
* @tc.name: GetRealPlaybackPosition003
* @tc.desc: GetRealPlaybackPosition after recive callback
* @tc.type: FUNC
* @tc.require: AR000H31JK
*/
HWTEST_F(AVSessionControllerTest, GetRealPlaybackPosition003, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackImpl> callback = std::make_shared<AVControllerCallbackImpl>();
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(controller_->RegisterCallback(callback), AVSESSION_SUCCESS);

    AVPlaybackState::PlaybackStateMaskType filter;
    filter.set();
    EXPECT_EQ(controller_->SetPlaybackFilter(filter), AVSESSION_SUCCESS);
    AVPlaybackState state;
    state.SetPosition({ TestMicroSecond * TestMicroSecond, TestMicroSecond });
    EXPECT_EQ(avsession_->SetAVPlaybackState(state), AVSESSION_SUCCESS);
    sleep(1);
    EXPECT_EQ(controller_->GetRealPlaybackPosition() > 0, true);
}