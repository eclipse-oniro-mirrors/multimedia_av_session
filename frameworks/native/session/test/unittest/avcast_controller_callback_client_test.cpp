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


#include "gtest/gtest.h"

#include "avcast_controller_callback_client.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "string_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {

class AVCastControllerCallbackImpl : public AVCastControllerCallback {
public:
    void OnCastPlaybackStateChange(const AVPlaybackState& state) override {};
    void OnMediaItemChange(const AVQueueItem& avQueueItem) override {};
    void OnPlayNext() override {};
    void OnPlayPrevious() override {};
    void OnSeekDone(const int32_t seekNumber) override {};
    void OnVideoSizeChange(const int32_t width, const int32_t height) override {};
    void OnPlayerError(const int32_t errorCode, const std::string& errorMsg) override {};
    void OnEndOfStream(const int32_t isLooping) override {};
    void OnPlayRequest(const AVQueueItem& avQueueItem) override {};
    void OnKeyRequest(const std::string &assetId, const std::vector<uint8_t> &keyRequestData) override {};
    void OnCastValidCommandChanged(const std::vector<int32_t>& cmds) override {};
    int32_t onDataSrcRead(const std::shared_ptr<AVSharedMemoryBase>& mem, uint32_t length,
                          int64_t pos, int32_t& result) override { return 0; };

    ~AVCastControllerCallbackImpl() override {};
};

class AVCastControllerCallbackClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVCastControllerCallbackClientTest::SetUpTestCase()
{}

void AVCastControllerCallbackClientTest::TearDownTestCase()
{}

void AVCastControllerCallbackClientTest::SetUp()
{}

void AVCastControllerCallbackClientTest::TearDown()
{}

/**
* @tc.name: OnCastPlaybackStateChange001
* @tc.desc: test OnCastPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnCastPlaybackStateChange001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    AVPlaybackState state;
    controllerCallbackClient->OnCastPlaybackStateChange(state);
}

/**
* @tc.name: OnMediaItemChange001
* @tc.desc: test OnMediaItemChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnMediaItemChange001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    AVQueueItem avQueueItem;
    controllerCallbackClient->OnMediaItemChange(avQueueItem);
}

/**
* @tc.name: OnPlayNext001
* @tc.desc: test OnPlayNext
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnPlayNext001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    controllerCallbackClient->OnPlayNext();
}

/**
* @tc.name: OnPlayPrevious001
* @tc.desc: test OnPlayPrevious
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnPlayPrevious001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    controllerCallbackClient->OnPlayPrevious();
}

/**
* @tc.name: OnSeekDone001
* @tc.desc: test OnSeekDone
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnSeekDone001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    int32_t seekNumber = 0;
    controllerCallbackClient->OnSeekDone(seekNumber);
}

/**
* @tc.name: OnVideoSizeChange001
* @tc.desc: test OnVideoSizeChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnVideoSizeChange001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    int32_t width = 0;
    int32_t height = 0;
    controllerCallbackClient->OnVideoSizeChange(width, height);
}

/**
* @tc.name: OnPlayerError001
* @tc.desc: test OnPlayerError
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnPlayerError001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    int32_t errorCode = 0;
    std::string errorMsg = "";
    controllerCallbackClient->OnPlayerError(errorCode, errorMsg);
}

/**
* @tc.name: OnEndOfStream001
* @tc.desc: test OnEndOfStream
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnEndOfStream001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    int32_t isLooping = 0;
    controllerCallbackClient->OnEndOfStream(isLooping);
}

/**
* @tc.name: OnPlayRequest001
* @tc.desc: test OnPlayRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnPlayRequest001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    AVQueueItem avQueueItem;
    controllerCallbackClient->OnPlayRequest(avQueueItem);
}

/**
* @tc.name: OnKeyRequest001
* @tc.desc: test OnKeyRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnKeyRequest001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    std::string assetId = "";
    std::vector<uint8_t> keyRequestData = {1};
    controllerCallbackClient->OnKeyRequest(assetId, keyRequestData);
}

/**
* @tc.name: OnCastValidCommandChanged001
* @tc.desc: test OnCastValidCommandChanged
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnCastValidCommandChanged001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    std::vector<int32_t> cmds = {1};
    controllerCallbackClient->OnCastValidCommandChanged(cmds);
}

/**
* @tc.name: onDataSrcRead001
* @tc.desc: test onDataSrcRead
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, onDataSrcRead001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    std::vector<int32_t> cmds = {1};
    std::shared_ptr<AVSharedMemoryBase> mem = nullptr;
    uint32_t length = 0;
    int64_t pos = 0;
    int32_t result = 0;
    controllerCallbackClient->onDataSrcRead(mem, length, pos, result);
}

/**
* @tc.name: OnCustomData001
* @tc.desc: test OnCustomData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVCastControllerCallbackClientTest, OnCustomData001, TestSize.Level1)
{
    std::shared_ptr<AVCastControllerCallback> controllerCallback = std::make_shared<AVCastControllerCallbackImpl>();
    std::shared_ptr<AVCastControllerCallbackClient> controllerCallbackClient =
        std::make_shared<AVCastControllerCallbackClient>(controllerCallback);
    EXPECT_NE(controllerCallbackClient, nullptr);
    std::string dataStr = "test";
    OHOS::AAFwk::WantParams data;
    data.SetParam("customData", OHOS::AAFwk::String::Box(dataStr));
    controllerCallbackClient->OnCustomData(data);
}
} // namespace AVSESSION
} // namespace OHOS