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
#include "avcast_controller_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {

class AVCastControllerProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    sptr<IAVCastController> avCastControllerProxy_;
};

void AVCastControllerProxyTest::SetUpTestCase()
{
}

void AVCastControllerProxyTest::TearDownTestCase()
{
}

void AVCastControllerProxyTest::SetUp()
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGI("failed to get sa mgr");
        return;
    }
    auto object = mgr->GetSystemAbility(OHOS::AVSESSION_SERVICE_ID);
    if (object == nullptr) {
        SLOGI("failed to get service");
        return;
    }
    avCastControllerProxy_ = iface_cast<IAVCastController>(object);
}

void AVCastControllerProxyTest::TearDown()
{
}

/**
 * @tc.name: GetDuration001
 * @tc.desc: Test GetDuration
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, GetDuration001, testing::ext::TestSize.Level0)
{
    SLOGI("GetDuration001, start");
    int32_t duration = 0;
    int32_t ret = avCastControllerProxy_->GetDuration(duration);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("GetDuration001, end");
}

/**
 * @tc.name: GetCastAVPlaybackState001
 * @tc.desc: Test GetCastAVPlaybackState
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, GetCastAVPlaybackState001, testing::ext::TestSize.Level0)
{
    SLOGI("GetCastAVPlaybackState001, start");
    AVPlaybackState state;
    int32_t ret = avCastControllerProxy_->GetCastAVPlaybackState(state);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetCastAVPlaybackState001, end");
}

/**
 * @tc.name: GetCurrentItem001
 * @tc.desc: Test GetCurrentItem
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, GetCurrentItem001, testing::ext::TestSize.Level0)
{
    SLOGI("GetCurrentItem001, start");
    AVQueueItem currentItem;
    int32_t ret = avCastControllerProxy_->GetCurrentItem(currentItem);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetCurrentItem001, end");
}

/**
 * @tc.name: GetValidCommands001
 * @tc.desc: Test GetValidCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, GetValidCommands001, testing::ext::TestSize.Level0)
{
    SLOGI("GetValidCommands001, start");
    std::vector<int32_t> cmds;
    int32_t ret = avCastControllerProxy_->GetValidCommands(cmds);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetValidCommands001, end");
}

/**
 * @tc.name: SetDisplaySurface001
 * @tc.desc: Test SetDisplaySurface
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, SetDisplaySurface001, testing::ext::TestSize.Level0)
{
    SLOGI("SetDisplaySurface001, start");
    std::string surfaceId = "1111";
    int32_t ret = avCastControllerProxy_->SetDisplaySurface(surfaceId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetDisplaySurface001, end");
}

/**
 * @tc.name: ProcessMediaKeyResponse001
 * @tc.desc: Test ProcessMediaKeyResponse
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, ProcessMediaKeyResponse001, testing::ext::TestSize.Level0)
{
    SLOGI("ProcessMediaKeyResponse001, start");
    std::string assetId = "";
    std::vector<uint8_t> response = {};
    int32_t ret = avCastControllerProxy_->ProcessMediaKeyResponse(assetId, response);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("ProcessMediaKeyResponse001, end");
}

/**
 * @tc.name: ProcessMediaKeyResponse002
 * @tc.desc: Test ProcessMediaKeyResponse
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, ProcessMediaKeyResponse002, testing::ext::TestSize.Level0)
{
    SLOGI("ProcessMediaKeyResponse002, start");
    std::string assetId = "";
    std::vector<uint8_t> response = {1, 0, 1};
    int32_t ret = avCastControllerProxy_->ProcessMediaKeyResponse(assetId, response);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("ProcessMediaKeyResponse002, end");
}

/**
 * @tc.name: ProcessMediaKeyResponse003
 * @tc.desc: Test ProcessMediaKeyResponse
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, ProcessMediaKeyResponse003, testing::ext::TestSize.Level0)
{
    SLOGI("ProcessMediaKeyResponse003, start");
    std::string assetId = "";
    std::vector<uint8_t> response(100000, 1);
    int32_t ret = avCastControllerProxy_->ProcessMediaKeyResponse(assetId, response);
    EXPECT_EQ(ret, ERR_IPC_SEND_REQUEST);
    SLOGI("ProcessMediaKeyResponse003, end");
}

/**
 * @tc.name: AddAvailableCommand001
 * @tc.desc: Test AddAvailableCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, AddAvailableCommand001, testing::ext::TestSize.Level0)
{
    SLOGI("AddAvailableCommand001, start");
    int32_t cmd = 0;
    int32_t ret = avCastControllerProxy_->AddAvailableCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("AddAvailableCommand001, end");
}

/**
 * @tc.name: RemoveAvailableCommand001
 * @tc.desc: Test RemoveAvailableCommand
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerProxyTest, RemoveAvailableCommand001, testing::ext::TestSize.Level0)
{
    SLOGI("RemoveAvailableCommand001, start");
    int32_t cmd = 0;
    int32_t ret = avCastControllerProxy_->RemoveAvailableCommand(cmd);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("RemoveAvailableCommand001, end");
}

} // namespace OHOS::AVSession