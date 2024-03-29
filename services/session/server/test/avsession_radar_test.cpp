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
#include "avsession_radar.h"
#include "avsession_log.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class AVSessionRadarTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    OutputDeviceInfo outDeviceInfo_;
};

void AVSessionRadarTest::SetUpTestCase()
{}

void AVSessionRadarTest::TearDownTestCase()
{}

void AVSessionRadarTest::SetUp()
{
    AVSessionRadar::GetInstance().InitBMS();
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = 1;
    deviceInfo.deviceId_ = "abcdefghijklmnopkrst";
    deviceInfo.deviceName_ = "phone";
    deviceInfo.networkId_ = "1234567890123456789";
    deviceInfo.deviceType_ = 0xE;
    deviceInfo.authenticationStatus_ = 0;
    outDeviceInfo_.deviceInfos_.push_back(deviceInfo);
}

void AVSessionRadarTest::TearDown()
{}

/**
* @tc.name: AVSessionRadarGetAnonymousDeviceId001
* @tc.desc: Get Anonymous DeviceId
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarGetAnonymousDeviceId001, TestSize.Level1)
{
    std::string deviceId = "abcdefghijklmnopkrst";
    std::string ret = AVSessionRadar::GetAnonymousDeviceId(deviceId);
    EXPECT_EQ(ret, "abcde**pkrst");
}

/**
* @tc.name: AVSessionRadarGetRadarErrorCode001
* @tc.desc: Get Radar ErrorCode
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarGetRadarErrorCode001, TestSize.Level1)
{
    int32_t error = -1020;
    int32_t ret = AVSessionRadar::GetRadarErrorCode(error);
    EXPECT_EQ(ret, 475137020);
}

/**
* @tc.name: AVSessionRadarGetPeerInfo001
* @tc.desc: get peer info from outputDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarGetPeerInfo001, TestSize.Level1)
{
    std::string deviceList;
    AVSessionRadarInfo info("AVSessionRadarGetPeerInfo001");
    AVSessionRadar::GetInstance().GetPeerInfo(outDeviceInfo_, info);
    EXPECT_EQ(info.peerBtMac_, "");
    EXPECT_EQ(info.peerDevType_, "00E");
    EXPECT_EQ(info.isTrust_, static_cast<int32_t>(TrustStatus::UNTRUST));
}

/**
* @tc.name: AVSessionRadarStartCastDiscoveryBegin001
* @tc.desc: Start Cast Discovery Begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarStartCastDiscoveryBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionRadarStartCastDiscoveryBegin001");
    AVSessionRadar::GetInstance().StartCastDiscoveryBegin(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionRadarStartCastDiscoveryEnd001
* @tc.desc: Start Cast Discovery End
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarStartCastDiscoveryEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionRadarStartCastDiscoveryEnd001");
    AVSessionRadar::GetInstance().StartCastDiscoveryEnd(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionRadarFailToStartCastDiscovery001
* @tc.desc: Fail To StartCastDiscovery
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarFailToStartCastDiscovery001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionRadarFailToStartCastDiscovery001");
    AVSessionRadar::GetInstance().FailToStartCastDiscovery(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionRadarCastDeviceAvailable001
* @tc.desc: Cast Device Available
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionRadarCastDeviceAvailable001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionRadarCastDeviceAvailable001");
    AVSessionRadar::GetInstance().CastDeviceAvailable(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::DISPLAY));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStopCastDiscoveryBegin001
* @tc.desc: Stop Cast Discovery Begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStopCastDiscoveryBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStopCastDiscoveryBegin001");
    AVSessionRadar::GetInstance().StopCastDiscoveryBegin(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::STOP));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionStopCastDiscoveryEnd001
* @tc.desc: Stop Cast Discovery End
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStopCastDiscoveryEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStopCastDiscoveryEnd001");
    AVSessionRadar::GetInstance().StopCastDiscoveryEnd(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::STOP));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToStopCastDiscovery001
* @tc.desc: Fail To Stop CastDiscovery
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToStopCastDiscovery001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToStopCastDiscovery001");
    AVSessionRadar::GetInstance().FailToStopCastDiscovery(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_DISCOVERY));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::STOP));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStartCastBegin001
* @tc.desc: Start Cast Begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartCastBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartCastBegin001");
    AVSessionRadar::GetInstance().StartCastBegin(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionStartCastEnd001
* @tc.desc: Start Cast End
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartCastEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartCastEnd001");
    AVSessionRadar::GetInstance().StartCastEnd(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastDiscoveryStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToStartCast001
* @tc.desc: Fail To StartCast
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToStartCast001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToStartCast001");
    AVSessionRadar::GetInstance().FailToStartCast(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToStartCast002
* @tc.desc: Fail To StartCast with outputDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToStartCast002, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToStartCast002");
    AVSessionRadar::GetInstance().FailToStartCast(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::START));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStartConnect001
* @tc.desc: Start Connect
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartConnect001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartConnect001");
    AVSessionRadar::GetInstance().StartConnect(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::CONNECT));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionConnectFinish001
* @tc.desc: Connect Finish
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionConnectFinish001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionConnectFinish001");
    AVSessionRadar::GetInstance().ConnectFinish(outDeviceInfo_.deviceInfos_[0], info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::CONNECT));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStartPlayBegin001
* @tc.desc: Start Play Begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartPlayBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartPlayBegin001");
    AVSessionRadar::GetInstance().StartPlayBegin(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::STARTED));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionStartPlayEnd001
* @tc.desc: Start Play End
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartPlayEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartPlayEnd001");
    AVSessionRadar::GetInstance().StartPlayEnd(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::STARTED));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStartPlayFailed001
* @tc.desc: Start Play Failed
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStartPlayFailed001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStartPlayFailed001");
    AVSessionRadar::GetInstance().StartPlayFailed(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::STARTED));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionPlayerStarted001
* @tc.desc: Player Started
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionPlayerStarted001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionPlayerStarted001");
    AVSessionRadar::GetInstance().PlayerStarted(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_START));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStartStage::STARTED));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionSendControlCommandBegin001
* @tc.desc: Send Control Command begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionSendControlCommandBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionSendControlCommandEnd001");
    AVSessionRadar::GetInstance().SendControlCommandBegin(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_CONTROL));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastControlStage::SEND_COMMAND));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionSendControlCommandEnd001
* @tc.desc: Send Control Command end
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionSendControlCommandEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionSendControlCommandEnd001");
    AVSessionRadar::GetInstance().SendControlCommandEnd(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_CONTROL));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastControlStage::SEND_COMMAND));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToSendControlCommand001
* @tc.desc: Fail To SendControlCommand
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToSendControlCommand001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToSendControlCommand001");
    AVSessionRadar::GetInstance().FailToSendControlCommand(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_CONTROL));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastControlStage::SEND_COMMAND));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionControlCommandRespond001
* @tc.desc: receive control command respond
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionControlCommandRespond001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionControlCommandRespond001");
    AVSessionRadar::GetInstance().ControlCommandRespond(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_CONTROL));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastControlStage::RECV_COMMAND));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionControlCommandError001
* @tc.desc: receive control command error respond
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionControlCommandError001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionControlCommandError001");
    AVSessionRadar::GetInstance().ControlCommandError(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_CONTROL));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastControlStage::RECV_COMMAND));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStopCastBegin001
* @tc.desc: invoke Stop Casting function Begin
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStopCastBegin001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStopCastBegin001");
    AVSessionRadar::GetInstance().StopCastBegin(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_END));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStopStage::STOP_BEGIN));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::IDLE));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::BEGIN));
}

/**
* @tc.name: AVSessionStopCastEnd001
* @tc.desc: invoke Stop Casting function End
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStopCastEnd001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStopCastEnd001");
    AVSessionRadar::GetInstance().StopCastEnd(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_END));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStopStage::STOP_BEGIN));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionStopCastFinish001
* @tc.desc: cast session is finished
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionStopCastFinish001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionStopCastFinish001");
    AVSessionRadar::GetInstance().StopCastFinish(outDeviceInfo_.deviceInfos_[0], info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_END));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStopStage::STOP_END));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::SUCCESS));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToStopCast001
* @tc.desc: Fail To Stop Cast
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToStopCast001, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToStopCast001");
    AVSessionRadar::GetInstance().FailToStopCast(info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_END));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStopStage::STOP_BEGIN));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}

/**
* @tc.name: AVSessionFailToStopCast002
* @tc.desc: Fail To Stop Cast with outputDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionRadarTest, AVSessionFailToStopCast002, TestSize.Level1)
{
    AVSessionRadarInfo info("AVSessionFailToStopCast002");
    AVSessionRadar::GetInstance().FailToStopCast(outDeviceInfo_, info);
    EXPECT_EQ(info.bizScene_, static_cast<int32_t>(BizScene::CAST_END));
    EXPECT_EQ(info.bizStage_, static_cast<int32_t>(CastStopStage::STOP_BEGIN));
    EXPECT_EQ(info.stageRes_, static_cast<int32_t>(StageResult::FAIL));
    EXPECT_EQ(info.bizState_, static_cast<int32_t>(BizState::END));
}