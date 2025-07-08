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
#include "av_cast_controller_callback_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_service.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {

class AVCastControllerCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    
    sptr<AVCastControllerCallbackProxy> avCastControllerCallbackProxy_;
};

void AVCastControllerCallbackProxyTest::SetUpTestCase()
{
}

void AVCastControllerCallbackProxyTest::TearDownTestCase()
{
}

void AVCastControllerCallbackProxyTest::SetUp()
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
    avCastControllerCallbackProxy_ = iface_cast<AVCastControllerCallbackProxy>(object);
}

void AVCastControllerCallbackProxyTest::TearDown()
{
}

/**
 * @tc.name: OnKeyRequest001
 * @tc.desc: Test OnKeyRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerCallbackProxyTest, OnKeyRequest001, testing::ext::TestSize.Level0)
{
    std::string assetId = "";
    std::vector<uint8_t> keyRequestData(100000, 0);
    avCastControllerCallbackProxy_->OnKeyRequest(assetId, keyRequestData);
    EXPECT_EQ(keyRequestData.empty(), false);
}

/**
 * @tc.name: OnKeyRequest002
 * @tc.desc: Test OnKeyRequest
 * @tc.type: FUNC
 */
static HWTEST_F(AVCastControllerCallbackProxyTest, OnKeyRequest002, testing::ext::TestSize.Level0)
{
    std::string assetId = "";
    std::vector<uint8_t> keyRequestData;
    avCastControllerCallbackProxy_->OnKeyRequest(assetId, keyRequestData);
    EXPECT_EQ(keyRequestData.empty(), true);
}

/**
* @tc.name: onDataSrcRead001
* @tc.desc: Test onDataSrcRead
* @tc.type: FUNC
*/
static HWTEST_F(AVCastControllerCallbackProxyTest, onDataSrcRead001, testing::ext::TestSize.Level0)
{
    std::shared_ptr<AVSharedMemoryBase> memory = AVSharedMemoryBase::CreateFromRemote(-1, 10, 1, "test");
    std::string assetId = "";
    std::vector<uint8_t> keyRequestData;
    int32_t result = 0;
    if (avCastControllerCallbackProxy_ != nullptr) {
        auto ret = avCastControllerCallbackProxy_->onDataSrcRead(memory, 2, 2, result);
        EXPECT_EQ(ret, ERR_INVALID_DATA);
    }
}
} // namespace OHOS::AVSession