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

#include "avcast_controller_callback_client.h"
#include "avcontroller_callback_client.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVControllerCallbackClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVControllerCallbackClientTest::SetUpTestCase()
{}

void AVControllerCallbackClientTest::TearDownTestCase()
{}

void AVControllerCallbackClientTest::SetUp()
{}

void AVControllerCallbackClientTest::TearDown()
{}

class AVControllerCallbackDemo : public AVControllerCallback {
public:
    void OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData) override {}

    void OnAVCallStateChange(const AVCallState& avCallState) override {}

    void OnSessionDestroy() override {}

    void OnPlaybackStateChange(const AVPlaybackState& state) override {}

    void OnMetaDataChange(const AVMetaData& data) override {}

    void OnActiveStateChange(bool isActive) override {}

    void OnValidCommandChange(const std::vector<int32_t>& cmds) override {}

    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override {}

    void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override {}

    void OnQueueItemsChange(const std::vector<AVQueueItem>& items) override {}

    void OnQueueTitleChange(const std::string& title) override {}

    void OnExtrasChange(const AAFwk::WantParams& extras) override {}

    ~AVControllerCallbackDemo() override {}
};

/**
* @tc.name: OnPlaybackStateChange001
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnPlaybackStateChange001, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVPlaybackState avplaybackState;
    aVControllerCallbackClient->OnPlaybackStateChange(avplaybackState);
}

/**
* @tc.name: OnPlaybackStateChange002
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnPlaybackStateChange002, TestSize.Level1)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVPlaybackState avplaybackState;
    aVControllerCallbackClient->AddListenerForPlaybackState([](const AVPlaybackState& state) {});
    aVControllerCallbackClient->OnPlaybackStateChange(avplaybackState);
}
} // namespace AVSession
} // namespace OHOS