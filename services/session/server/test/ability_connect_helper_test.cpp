/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "avsession_descriptor.h"
#include "avsession_errors.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "ability_connect_helper.h"
#include "insight_intent_execute_param.h"

using namespace testing::ext;
using namespace OHOS::AVSession;
constexpr int32_t DESKTOP_LYRICS_ABILITY_CONNECTED = 2;
constexpr int32_t DESKTOP_LYRICS_ABILITY_DISCONNECTED = 4;

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
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest001, TestSize.Level0)
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
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest002, TestSize.Level0)
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
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest003, TestSize.Level0)
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
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest004, TestSize.Level0)
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
static HWTEST(AbilityConnectHelperTest, OnRemoteRequest005, TestSize.Level0)
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

/**
 * @tc.name: OnAbilityConnectDone001
 * @tc.desc: Test OnAbilityConnect with normal branch
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, OnAbilityConnectDone001, TestSize.Level0)
{
    SLOGI("OnAbilityConnectDone001 begin!");
    OHOS::sptr<DesktopLyricCallConnection> connect = new (std::nothrow) DesktopLyricCallConnection(nullptr);
    ASSERT_NE(connect, nullptr);

    OHOS::AppExecFwk::ElementName element;
    connect->OnAbilityConnectDone(element, nullptr, 0);

    int32_t ret = 0;
    connect->callback_ = [&ret](int32_t in){ ret = in; };
    connect->OnAbilityConnectDone(element, nullptr, 0);
    EXPECT_EQ(ret, DESKTOP_LYRICS_ABILITY_CONNECTED);
}

/**
 * @tc.name: OnAbilityDisconnectDone001
 * @tc.desc: Test OnAbilityDisconnectDone
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, OnAbilityDisconnectDone001, TestSize.Level0)
{
    SLOGI("OnAbilityDisconnectDone001 begin!");
    OHOS::sptr<DesktopLyricCallConnection> connect = new (std::nothrow) DesktopLyricCallConnection(nullptr);
    ASSERT_NE(connect, nullptr);

    OHOS::AppExecFwk::ElementName element;
    connect->OnAbilityDisconnectDone(element, 0);

    int32_t ret = 0;
    connect->callback_ = [&ret](int32_t in){ ret = in; };
    connect->OnAbilityDisconnectDone(element, 0);
    EXPECT_EQ(ret, DESKTOP_LYRICS_ABILITY_DISCONNECTED);
}

/**
 * @tc.name: StartAbilityForegroundByCall001
 * @tc.desc: Test StartAbilityForegroundByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityConnectHelperTest, StartAbilityForegroundByCall001, TestSize.Level0)
{
    SLOGI("StartAbilityForegroundByCall001 begin!");
    std::string bundleName;
    std::string abilityName;
    int32_t ret = AbilityConnectHelper::GetInstance().StartAbilityForegroundByCall(bundleName, abilityName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: StartAbilityForegroundByCall002
 * @tc.desc: Test StartAbilityForegroundByCall
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST(AbilityConnectHelperTest, StartAbilityForegroundByCall002, TestSize.Level0)
{
    SLOGI("StartAbilityForegroundByCall002 begin!");
    std::string bundleName = "com.ohos.camera";
    std::string abilityName = "test.ability";
    int32_t ret = AbilityConnectHelper::GetInstance().StartAbilityForegroundByCall(bundleName, abilityName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: StartAbilityByCall001
 * @tc.desc: Test StartAbilityByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityConnectHelperTest, StartAbilityByCall001, TestSize.Level0)
{
    SLOGI("StartAbilityByCall001 begin!");
    std::string bundleName;
    std::string abilityName;
    int32_t ret = AbilityConnectHelper::GetInstance().StartAbilityByCall(bundleName, abilityName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: StartAbilityByCall002
 * @tc.desc: Test StartAbilityByCall
 * @tc.type: FUNC
 */
static HWTEST(AbilityConnectHelperTest, StartAbilityByCall002, TestSize.Level0)
{
    SLOGI("StartAbilityByCall002 begin!");
    std::string bundleName = "com.ohos.camera";
    std::string abilityName = "test.ability";
    int32_t ret = AbilityConnectHelper::GetInstance().StartAbilityByCall(bundleName, abilityName);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ConnectAbilityCommon001
 * @tc.desc: Test ConnectAbilityCommon
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, ConnectAbilityCommon001, TestSize.Level0)
{
    SLOGI("ConnectAbilityCommon001 begin!");
    OHOS::AAFwk::Want want;
    int32_t ret = ExtensionConnectHelper::GetInstance().ConnectAbilityCommon(want, nullptr, 0);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
}

/**
 * @tc.name: ConnectAbilityCommon002
 * @tc.desc: Test ConnectAbilityCommon
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, ConnectAbilityCommon002, TestSize.Level0)
{
    SLOGI("ConnectAbilityCommon002 begin!");
    OHOS::AAFwk::Want want;
    OHOS::sptr<DesktopLyricCallConnection> connect = new (std::nothrow) DesktopLyricCallConnection(nullptr);
    ASSERT_NE(connect, nullptr);
    int32_t ret = ExtensionConnectHelper::GetInstance().ConnectAbilityCommon(want, connect, 0);
    EXPECT_NE(ret, ERR_INVALID_PARAM);
}

/**
 * @tc.name: DisconnectAbility001
 * @tc.desc: Test DisconnectAbility001
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, DisconnectAbility001, TestSize.Level0)
{
    SLOGI("DisconnectAbility001 begin!");
    int32_t ret = ExtensionConnectHelper::GetInstance().DisconnectAbility(nullptr);
    EXPECT_EQ(ret, ERR_INVALID_PARAM);
}

/**
 * @tc.name: DisconnectAbility002
 * @tc.desc: Test DisconnectAbility
 * @tc.type: FUNC
 * @tc.require: #1998
 */
static HWTEST(AbilityConnectHelperTest, DisconnectAbility002, TestSize.Level0)
{
    SLOGI("DisconnectAbility002 begin!");
    OHOS::AAFwk::Want want;
    OHOS::sptr<DesktopLyricCallConnection> connect = new (std::nothrow) DesktopLyricCallConnection(nullptr);
    ASSERT_NE(connect, nullptr);
    int32_t ret = ExtensionConnectHelper::GetInstance().DisconnectAbility(connect);
    EXPECT_NE(ret, ERR_INVALID_PARAM);
}