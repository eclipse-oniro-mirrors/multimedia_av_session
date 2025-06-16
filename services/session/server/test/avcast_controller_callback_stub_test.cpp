/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "avcast_controller_callback_stub.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "token_setproc.h"
#include "av_shared_memory_base.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AVSession {

static uint64_t g_selfTokenId = 0;
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
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        }
    }
};

class AVCastControllerCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVCastControllerCallbackStubTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenKit::AllocHapToken(g_info, g_policy);
    AccessTokenIDEx tokenID = AccessTokenKit::GetHapTokenIDEx(g_info.userID, g_info.bundleName, g_info.instIndex);
    SetSelfTokenID(tokenID.tokenIDEx);
}

void AVCastControllerCallbackStubTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    auto tokenId = AccessTokenKit::GetHapTokenID(g_info.userID, g_info.bundleName, g_info.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
}

void AVCastControllerCallbackStubTest::SetUp()
{}

void AVCastControllerCallbackStubTest::TearDown()
{}

class AVCastControllerCallbackStubDemo : public AVCastControllerCallbackStub {
public:
    void OnCastPlaybackStateChange(const AVPlaybackState& state) override {}

    void OnMediaItemChange(const AVQueueItem& avQueueItem) override {}

    void OnPlayNext() override {}

    void OnPlayPrevious() override {}

    void OnSeekDone(const int32_t seekNumber) override {}

    void OnVideoSizeChange(const int32_t width, const int32_t height) override {}

    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override {}

    void OnEndOfStream(const int32_t isLooping) override {}

    void OnPlayRequest(const AVQueueItem& avQueueItem) override {}

    void OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData) override {}

    void OnCastValidCommandChanged(const std::vector<int32_t> &cmds) override {}
};

/**
* @tc.name: OnRemoteRequest001
* @tc.desc: test OnRemoteRequest with failed code
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest001, TestSize.Level1)
{
    uint32_t code = 100;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
* @tc.name: OnRemoteRequest002
* @tc.desc: test OnRemoteRequest with failed Descriptor
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest002, TestSize.Level1)
{
    uint32_t code = 100;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: OnRemoteRequest003
* @tc.desc: test HandleOnKeyRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest003, TestSize.Level1)
{
    uint32_t code = 9;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_NONE);
}

/**
* @tc.name: OnRemoteRequest004
* @tc.desc: test HandleOnKeyRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest004, TestSize.Level1)
{
    uint32_t code = 9;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    data.WriteString("***");
    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    void* ptr = nullptr;
    data.WriteBuffer(ptr, 0);
    data.WriteInt32(1);

    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, INVALID_FD);
}

/**
* @tc.name: OnRemoteRequest005
* @tc.desc: test HandleOnKeyRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest005, TestSize.Level1)
{
    uint32_t code = 9;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    data.WriteString("***");
    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    std::string str{"0000"};
    data.WriteBuffer(str.c_str(), 4);
    data.WriteInt32(0);

    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, INVALID_FD);
}

/**
* @tc.name: OnRemoteRequest006
* @tc.desc: test HandleOnKeyRequest
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, OnRemoteRequest006, TestSize.Level1)
{
    uint32_t code = 9;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    data.WriteString("***");
    auto localDescriptor = IAVCastControllerCallback::GetDescriptor();
    data.WriteInterfaceToken(localDescriptor);
    std::string str{"0000"};
    data.WriteBuffer(str.c_str(), 4);
    data.WriteInt32(4);

    int ret = avCastControllerCallbackStubDemo.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, INVALID_FD);
}

/**
* @tc.name: onDataSrcRead001
* @tc.desc: test onDataSrcRead when memory equal nullptr
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackStubTest, onDataSrcRead001, TestSize.Level1)
{
    std::shared_ptr<AVSharedMemory> memory = nullptr;
    AVCastControllerCallbackStubDemo avCastControllerCallbackStubDemo;
    auto ret = avCastControllerCallbackStubDemo.onDataSrcRead(memory, 1, 1);
    EXPECT_EQ(ret, 0);
}
} // namespace OHOS
} // namespace AVSession
