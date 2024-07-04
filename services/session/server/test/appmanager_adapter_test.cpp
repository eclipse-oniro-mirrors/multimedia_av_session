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
#include <string>
#include "app_manager_adapter.h"
#include "avsession_log.h"

using OHOS::AppExecFwk::AppData;
using OHOS::AppExecFwk::AppProcessData;
using OHOS::AVSession::AppManagerAdapter;

static int32_t g_expectedUid;
static AppData g_appData;
static AppProcessData g_appProcessData;

class AppManagerAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static constexpr int32_t TEST_UID = 3;
    static constexpr int32_t OTHER_UID_1 = 5;
    static constexpr int32_t OTHER_UID_2 = 4;
    static constexpr int32_t TEST_PID = 1;
    static constexpr int32_t INVALID_UID = -1;
};

void AppManagerAdapterTest::SetUpTestCase()
{
    std::string appName = "zhifubao";
    g_appData.appName = appName;
    g_appData.uid = AppManagerAdapterTest::TEST_UID ;
    g_appProcessData.processName = appName;
    g_appProcessData.pid = AppManagerAdapterTest::TEST_PID;
    g_appProcessData.appDatas.push_back(g_appData);
    OHOS::AVSession::AppManagerAdapter::GetInstance().SetAppBackgroundStateObserver([](int32_t uid, int32_t pid) {
        g_expectedUid = uid;
    });
    OHOS::AVSession::AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange([](int uid, int state) {
        SLOGI("serviceCallback For AppManagerAdapterTest uid = %{public}d, state = %{public}d", uid, state);
    });
}

void AppManagerAdapterTest::TearDownTestCase()
{
}

void AppManagerAdapterTest::TearDown()
{
}

void AppManagerAdapterTest::SetUp()
{
    g_expectedUid = INVALID_UID;
    g_appProcessData.appState = OHOS::AppExecFwk::ApplicationState::APP_STATE_BACKGROUND;
}

static void AppStateChangeCallback(int uid, int state)
{
    SLOGI("OnAppStateChangeCallback in AppManagerAdapterTest, check %{public}d, %{public}d", uid, state);
}

/**
* @tc.name: OnAppStateChanged001
* @tc.desc: Verify successfully received changes
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged001, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged001, start");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(TEST_UID);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(TEST_UID);
    EXPECT_EQ(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged001, end");
}

/**
* @tc.name: OnAppStateChanged002
* @tc.desc: Validation failed to receive changes
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged002, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged002, start");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(OTHER_UID_1);
    EXPECT_NE(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged002, end");
}

/**
* @tc.name: OnAppStateChanged003
* @tc.desc: Influence of state on change
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged003, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged003, start");
    g_appProcessData.appState = OHOS::AppExecFwk::ApplicationState::APP_STATE_FOREGROUND;
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(TEST_UID);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(TEST_UID);
    EXPECT_NE(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged003, end");
}

/**
* @tc.name: OnAppStateChanged004
* @tc.desc: Influence of state on change
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged004, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged004, start");
    g_appProcessData.appState = OHOS::AppExecFwk::ApplicationState::APP_STATE_FOREGROUND;
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(OTHER_UID_1);
    EXPECT_NE(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged004, end");
}

/**
* @tc.name: OnAppStateChanged005
* @tc.desc: Impact of deleting data on change
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged005, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged005, start");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(TEST_UID);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    EXPECT_EQ(g_expectedUid, g_appData.uid);
    g_expectedUid = INVALID_UID;
    AppManagerAdapter::GetInstance().RemoveObservedApp(TEST_UID);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    EXPECT_NE(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged005, end");
}

/**
* @tc.name: OnAppStateChanged006
* @tc.desc: Impact of more data on change
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged006, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged006, start");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().AddObservedApp(TEST_UID);
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_2);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().RemoveObservedApp(TEST_UID);
    EXPECT_EQ(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged006, end");
}

/**
* @tc.name: OnAppStateChanged007
* @tc.desc: The impact of more data but no correct data on change
* @tc.type: FUNC
* @tc.require: AR000H31KJ
*/
static HWTEST_F(AppManagerAdapterTest, OnAppStateChanged007, testing::ext::TestSize.Level1)
{
    SLOGI("OnAppStateChanged007, start");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().AddObservedApp(OTHER_UID_2);
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange(AppStateChangeCallback);
    AppManagerAdapter::GetInstance().HandleAppStateChanged(g_appProcessData);
    AppManagerAdapter::GetInstance().RemoveObservedApp(OTHER_UID_1);
    AppManagerAdapter::GetInstance().RemoveObservedApp(OTHER_UID_2);
    EXPECT_NE(g_expectedUid, g_appData.uid);
    SLOGI("OnAppStateChanged007, end");
}