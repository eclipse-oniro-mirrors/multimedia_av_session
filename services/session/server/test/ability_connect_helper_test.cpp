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
#include "background_audio_controller.h"
#include "avsession_log.h"
#include "message_parcel.h"
#include "ability_connect_callback_interface.h"
#include "ability_manager_interface.h"
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ability_connect_helper.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class AbilityConnectHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AbilityConnectHelperTest::SetUpTestCase()
{
}

void AbilityConnectHelperTest::TearDownTestCase()
{
}

void AbilityConnectHelperTest::SetUp()
{
}

void AbilityConnectHelperTest::TearDown()
{
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: #I62OZV
 */
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest001, TestSize.Level1)
{
    SLOGI("OnRemoteRequest001 begin!");
    uint32_t code = OHOS::AAFwk::IAbilityConnection::ON_ABILITY_DISCONNECT_DONE;
    AbilityConnectCallback abilityconnectcallback;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    int ret = abilityconnectcallback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: AAFwk::IAbilityConnection::ON_ABILITY_DISCONNECT_DONE
 * @tc.type: FUNC
 * @tc.require: #I62OZV
 */
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest002, TestSize.Level1)
{
    SLOGI("OnRemoteRequest002 begin!");
    uint32_t code = OHOS::AAFwk::IAbilityConnection::ON_ABILITY_DISCONNECT_DONE;
    AbilityConnectCallback abilityconnectcallback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::AbilityConnectionStub::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = abilityconnectcallback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: AAFwk::IAbilityConnection::ON_ABILITY_CONNECT_DONE&&remoteObject == nullptr
 * @tc.type: FUNC
 * @tc.require: #I62OZV
 */
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest003, TestSize.Level1)
{
    SLOGI("OnRemoteRequest003 begin!");
    uint32_t code = OHOS::AAFwk::IAbilityConnection::ON_ABILITY_CONNECT_DONE;
    AbilityConnectCallback abilityconnectcallback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::AbilityConnectionStub::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = abilityconnectcallback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: AAFwk::IAbilityConnection::ON_ABILITY_CONNECT_DONE
 * @tc.type: FUNC
 * @tc.require: #I62OZV
 */
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest004, TestSize.Level1)
{
    SLOGI("OnRemoteRequest004 begin!");
    uint32_t code = OHOS::AAFwk::IAbilityConnection::ON_ABILITY_CONNECT_DONE;
    AbilityConnectCallback abilityconnectcallback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::AbilityConnectionStub::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    OHOS::sptr<OHOS::AAFwk::IAbilityConnection> connect = new (std::nothrow) AbilityConnectCallback();
    if (connect == nullptr) {
        SLOGI("OnRemoteRequest004 connect is nullptr");
    }
    SLOGI("OnRemoteRequest004 connect is success");
    data.WriteRemoteObject(connect->AsObject());
    int ret = abilityconnectcallback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::AVSession::AVSESSION_ERROR);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: uint32_t code = 3;
 * @tc.type: FUNC
 * @tc.require: #I62OZV
 */
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest005, TestSize.Level1)
{
    SLOGI("OnRemoteRequest005 begin!");
    uint32_t code = 3;
    AbilityConnectCallback abilityconnectcallback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(OHOS::AVSession::AbilityConnectionStub::GetDescriptor());
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::AAFwk::Want want;
    OHOS::AppExecFwk::ElementName element("", "12345", "12345");
    want.SetElement(element);
    data.WriteParcelable(&want);
    int ret = abilityconnectcallback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OHOS::IPC_STUB_UNKNOW_TRANS_ERR);
}