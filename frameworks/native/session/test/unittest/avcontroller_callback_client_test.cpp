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

    void OnCustomData(const OHOS::AAFwk::WantParams& data) override {};

    ~AVControllerCallbackDemo() override {}
};

/**
* @tc.name: OnSessionDestroy001
* @tc.desc: test OnSessionDestroy
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnSessionDestroy001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    aVControllerCallbackClient->OnSessionDestroy();
}

/**
* @tc.name: OnAVCallMetaDataChange001
* @tc.desc: test OnAVCallMetaDataChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnAVCallMetaDataChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVCallMetaData data;
    aVControllerCallbackClient->OnAVCallMetaDataChange(data);
}

/**
* @tc.name: OnAVCallStateChange001
* @tc.desc: test OnAVCallStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnAVCallStateChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVCallState state;
    aVControllerCallbackClient->OnAVCallStateChange(state);
}

/**
* @tc.name: OnPlaybackStateChange001
* @tc.desc: test OnPlaybackStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnPlaybackStateChange001, TestSize.Level0)
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
HWTEST_F(AVControllerCallbackClientTest, OnPlaybackStateChange002, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVPlaybackState avplaybackState;
    aVControllerCallbackClient->AddListenerForPlaybackState([](const AVPlaybackState& state) {});
    aVControllerCallbackClient->OnPlaybackStateChange(avplaybackState);
}

/**
* @tc.name: OnMetaDataChange001
* @tc.desc: test OnMetaDataChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnMetaDataChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AVMetaData data;
    aVControllerCallbackClient->OnMetaDataChange(data);
}

/**
* @tc.name: OnActiveStateChange001
* @tc.desc: test OnActiveStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnActiveStateChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    bool isActive = true;
    aVControllerCallbackClient->OnActiveStateChange(isActive);
}

/**
* @tc.name: OnValidCommandChange001
* @tc.desc: test OnValidCommandChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnValidCommandChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    std::vector<int32_t> cmds = {1, 2, 3};
    aVControllerCallbackClient->OnValidCommandChange(cmds);
}

/**
* @tc.name: OnOutputDeviceChange001
* @tc.desc: test OnOutputDeviceChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnOutputDeviceChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    int32_t connectionState = 1;
    OutputDeviceInfo info;
    aVControllerCallbackClient->OnOutputDeviceChange(connectionState, info);
}

/**
* @tc.name: OnSessionEventChange001
* @tc.desc: test OnSessionEventChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnSessionEventChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    std::string event = "";
    AAFwk::WantParams args;
    aVControllerCallbackClient->OnSessionEventChange(event, args);
}

/**
* @tc.name: OnQueueItemsChange001
* @tc.desc: test OnQueueItemsChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnQueueItemsChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    std::vector<AVQueueItem> items;
    aVControllerCallbackClient->OnQueueItemsChange(items);
}

/**
* @tc.name: OnQueueTitleChange001
* @tc.desc: test OnQueueTitleChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnQueueTitleChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    std::string title = "test";
    aVControllerCallbackClient->OnQueueTitleChange(title);
}

/**
* @tc.name: OnExtrasChange001
* @tc.desc: test OnExtrasChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnExtrasChange001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AAFwk::WantParams extras;
    aVControllerCallbackClient->OnExtrasChange(extras);
}

/**
* @tc.name: OnCustomData001
* @tc.desc: test OnCustomData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnCustomData001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    EXPECT_NE(aVControllerCallbackClient, nullptr);
    AAFwk::WantParams data;
    aVControllerCallbackClient->OnCustomData(data);
}

/**
* @tc.name: OnDesktopLyricVisibilityChanged001
* @tc.desc: test OnDesktopLyricVisibilityChanged
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVControllerCallbackClientTest, OnDesktopLyricVisibilityChanged001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    ASSERT_NE(aVControllerCallbackClient, nullptr);
    ErrCode ret = aVControllerCallbackClient->OnDesktopLyricVisibilityChanged(true);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OnDesktopLyricStateChanged001
 * @tc.desc: test OnDesktopLyricStateChanged
 * @tc.type: FUNC
 * @tc.require: #1998
 */
HWTEST_F(AVControllerCallbackClientTest, OnDesktopLyricStateChanged001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    ASSERT_NE(aVControllerCallbackClient, nullptr);
    DesktopLyricState state = {};
    ErrCode ret = aVControllerCallbackClient->OnDesktopLyricStateChanged(state);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OnDesktopLyricEnabled001
 * @tc.desc: test OnDesktopLyricEnabled
 * @tc.type: FUNC
 * @tc.require: #1998
 */
HWTEST_F(AVControllerCallbackClientTest, OnDesktopLyricEnabled001, TestSize.Level0)
{
    std::shared_ptr<AVControllerCallbackDemo> ptr = std::make_shared<AVControllerCallbackDemo>();
    std::shared_ptr<AVControllerCallbackClient> aVControllerCallbackClient =
        std::make_shared<AVControllerCallbackClient>(ptr);
    ASSERT_NE(aVControllerCallbackClient, nullptr);
    ErrCode ret = aVControllerCallbackClient->OnDesktopLyricEnabled(false);
    EXPECT_EQ(ret, 0);
}

} // namespace AVSession
} // namespace OHOS