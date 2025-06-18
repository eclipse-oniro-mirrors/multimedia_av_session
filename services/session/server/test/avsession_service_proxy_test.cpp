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
#include "avsession_log.h"
#include "avsession_errors.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iservice_registry.h"
#include "avmedia_description.h"
#include "av_file_descriptor.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avsession_service_proxy.h"

using namespace OHOS;
using namespace OHOS::AVSession;
using namespace OHOS::Security::AccessToken;

class AVSessionServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionServiceProxyTest::SetUpTestCase()
{
}

void AVSessionServiceProxyTest::TearDownTestCase()
{
}

void AVSessionServiceProxyTest::SetUp()
{
}

void AVSessionServiceProxyTest::TearDown()
{
}

/**
 * @tc.name: GetAllSessionDescriptors001
 * @tc.desc: Test GetAllSessionDescriptors
 * @tc.type: FUNC
 */
static HWTEST_F(AVSessionServiceProxyTest, GetAllSessionDescriptors001, testing::ext::TestSize.Level1)
{
    SLOGI("GetAllSessionDescriptors001, start");

    int32_t ret = AVSESSION_ERROR;

    sptr<ISystemAbilityManager> mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("failed to get sa mgr");
        return;
    }
    sptr<IRemoteObject> sessionService = mgr->GetSystemAbility(AVSESSION_SERVICE_ID);
    if (sessionService == nullptr) {
        SLOGE("failed to get service");
        return;
    }

    std::string tag = "tag";
    int32_t type = OHOS::AVSession::AVSession::SESSION_TYPE_VOICE_CALL;
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    AppExecFwk::ElementName elementName(deviceId, bundleName, abilityName, moduleName);

    std::shared_ptr<AVSessionServiceProxy> avSessionServiceProxy =
        std::make_shared<AVSessionServiceProxy>(sessionService);

    std::shared_ptr<OHOS::AVSession::AVSession> session;
    ret = avSessionServiceProxy->CreateSession(tag, type, elementName, session);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(session != nullptr);

    std::vector<AVSessionDescriptor> descriptors;
    ret = avSessionServiceProxy->GetAllSessionDescriptors(descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(descriptors[0].sessionId_ != "");

    session = nullptr;
    sessionService = nullptr;
    avSessionServiceProxy = nullptr;
    SLOGI("GetAllSessionDescriptors001, end");
}
