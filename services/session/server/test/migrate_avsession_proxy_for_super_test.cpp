/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <chrono>
#include <thread>
#include <mutex>

#include "avsession_service.h"
#include "avsession_errors.h"
#include "avsession_item.h"
#include "avsession_log.h"
#include "migrate_avsession_proxy.h"
#include "migrate_avsession_constant.h"
#include "system_ability_definition.h"
#include "softbus/softbus_session_utils.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "base64_utils.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AVSession;

static OHOS::sptr<AVSessionService> g_avSessionService {nullptr};
static std::shared_ptr<MigrateAVSessionProxy> g_migrateAVSessionProxyForSuper {nullptr};

class MigrateAVSessionProxyForSuperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MigrateAVSessionProxyForSuperTest::SetUpTestCase()
{
    SLOGI("MigrateAVSessionProxyForSuperTest SetUpTestCase");
    g_avSessionService = new AVSessionService(OHOS::AVSESSION_SERVICE_ID);
    g_migrateAVSessionProxyForSuper = std::make_shared<MigrateAVSessionProxy>(
        g_avSessionService, MSG_HEAD_MODE_FOR_NEXT, "test_device_id");
}

void MigrateAVSessionProxyForSuperTest::TearDownTestCase()
{
    SLOGI("MigrateAVSessionProxyForSuperTest TearDownTestCase");
}

void MigrateAVSessionProxyForSuperTest::SetUp()
{
    SLOGI("MigrateAVSessionProxyForSuperTest SetUp");
    // Clean up global state to prevent test pollution
    if (g_migrateAVSessionProxyForSuper != nullptr) {
        g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
        g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    }
}

void MigrateAVSessionProxyForSuperTest::TearDown()
{
    SLOGI("MigrateAVSessionProxyForSuperTest TearDown");
    // Clean up global state to prevent test pollution
    if (g_migrateAVSessionProxyForSuper != nullptr) {
        g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
        g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    }
}

/**
 * @tc.name: HandlePlayForSuper001
 * @tc.desc: Test HandlePlayForSuper with empty playerId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayForSuper001, TestSize.Level0)
{
    std::string playerId = "";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayForSuper002
 * @tc.desc: Test HandlePlayForSuper with valid playerId but no session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayForSuper002, TestSize.Level0)
{
    std::string playerId = "test_player_id";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayForSuper003
 * @tc.desc: Test HandlePlayForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayForSuper003, TestSize.Level1)
{
    // Create a session for testing
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_001";
    descriptor.sessionTag_ = "test_tag";
    descriptor.sessionType_ = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    descriptor.elementName_.SetBundleName("com.test.bundle");
    descriptor.elementName_.SetAbilityName("MainAbility");
    descriptor.isThirdPartyApp_ = false;
    
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    ASSERT_NE(sessionItem, nullptr);
    
    // Add to session stack
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_001"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayForSuper("test_session_001");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    // Clean up
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: HandlePauseForSuper001
 * @tc.desc: Test HandlePauseForSuper with empty playerId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePauseForSuper001, TestSize.Level0)
{
    std::string playerId = "";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePauseForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePauseForSuper002
 * @tc.desc: Test HandlePauseForSuper with valid playerId but no session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePauseForSuper002, TestSize.Level0)
{
    std::string playerId = "test_player_id";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePauseForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayNextForSuper001
 * @tc.desc: Test HandlePlayNextForSuper with empty playerId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayNextForSuper001, TestSize.Level0)
{
    std::string playerId = "";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayNextForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayNextForSuper002
 * @tc.desc: Test HandlePlayNextForSuper with valid playerId but no session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayNextForSuper002, TestSize.Level0)
{
    std::string playerId = "test_player_id";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayNextForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayPreviousForSuper001
 * @tc.desc: Test HandlePlayPreviousForSuper with empty playerId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayPreviousForSuper001, TestSize.Level0)
{
    std::string playerId = "";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayPreviousForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandlePlayPreviousForSuper002
 * @tc.desc: Test HandlePlayPreviousForSuper with valid playerId but no session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayPreviousForSuper002, TestSize.Level0)
{
    std::string playerId = "test_player_id";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayPreviousForSuper(playerId);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: HandleToggleFavoriteForSuper001
 * @tc.desc: Test HandleToggleFavoriteForSuper with empty parameters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandleToggleFavoriteForSuper001, TestSize.Level0)
{
    std::string mediaId = "";
    std::string playerId = "";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandleToggleFavoriteForSuper(mediaId, playerId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: HandleToggleFavoriteForSuper002
 * @tc.desc: Test HandleToggleFavoriteForSuper with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandleToggleFavoriteForSuper002, TestSize.Level0)
{
    std::string mediaId = "test_media_id";
    std::string playerId = "test_player_id";
    int32_t ret = g_migrateAVSessionProxyForSuper->HandleToggleFavoriteForSuper(mediaId, playerId);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: GetControllerListForSuper001
 * @tc.desc: Test GetControllerListForSuper with empty stacks
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, GetControllerListForSuper001, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    std::vector<OHOS::sptr<IRemoteObject>> controllerList;
    int32_t ret = g_migrateAVSessionProxyForSuper->GetControllerListForSuper(controllerList);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(controllerList.empty());
}

/**
 * @tc.name: GetControllerListForSuper002
 * @tc.desc: Test GetControllerListForSuper with valid controllers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, GetControllerListForSuper002, TestSize.Level1)
{
    // Create a session and controller
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_002";
    descriptor.sessionTag_ = "test_tag";
    descriptor.sessionType_ = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
    
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    ASSERT_NE(sessionItem, nullptr);
    
    OHOS::sptr<AVControllerItem> controllerItem = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem);
    ASSERT_NE(controllerItem, nullptr);
    
    // Add to stacks
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_002"] = sessionItem;
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_["test_session_002"] = controllerItem;
    
    std::vector<OHOS::sptr<IRemoteObject>> controllerList;
    int32_t ret = g_migrateAVSessionProxyForSuper->GetControllerListForSuper(controllerList);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(controllerList.size(), 1);
    
    // Clean up
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: OnConnectForSuper001
 * @tc.desc: Test OnConnectForSuper returns success
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnConnectForSuper001, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->OnConnectForSuper();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnDisconnectForSuper001
 * @tc.desc: Test OnDisconnectForSuper returns success
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnDisconnectForSuper001, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->OnDisconnectForSuper();
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnBytesRecvForSuper001
 * @tc.desc: Test OnBytesRecvForSuper with too short data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper001, TestSize.Level0)
{
    std::string deviceId = "test_device";
    std::string data = "a"; // Too short (less than MSG_HEAD_LENGTH)
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: OnBytesRecvForSuper002
 * @tc.desc: Test OnBytesRecvForSuper with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper002, TestSize.Level0)
{
    std::string deviceId = "test_device";
    std::string data = "abinvalid_json";
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: OnBytesRecvForSuper003
 * @tc.desc: Test OnBytesRecvForSuper with SYNC_CONTROLLER_LIST type
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper003, TestSize.Level1)
{
    std::string deviceId = "test_device";
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    char* jsonStr = cJSON_PrintUnformatted(jsonValue);
    std::string data = std::string("ab") + std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnBytesRecvForSuper004
 * @tc.desc: Test OnBytesRecvForSuper with SYNC_CONTROLLER type
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper004, TestSize.Level1)
{
    std::string deviceId = "test_device";
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED);
    
    char* jsonStr = cJSON_PrintUnformatted(jsonValue);
    std::string data = std::string(1, (char)MSG_HEAD_MODE_FOR_NEXT) +
                       std::string(1, (char)SYNC_CONTROLLER) +
                       std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ProcessControllerListForSuper001
 * @tc.desc: Test ProcessControllerListForSuper with empty list
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper001, TestSize.Level1)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    // Add a test session first
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_old";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_old"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.empty());
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessControllerListForSuper002
 * @tc.desc: Test ProcessControllerListForSuper with valid controller
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper002, TestSize.Level1)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON* controllerInfo = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, "test_session_003");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.test.bundle");
    cJSON_AddItemToArray(controllerList, controllerInfo);
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerForSuper001
 * @tc.desc: Test ProcessControllerForSuper with invalid media info
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerForSuper001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, -1);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessControllerForSuper002
 * @tc.desc: Test ProcessControllerForSuper with metadata changed
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerForSuper002, TestSize.Level1)
{
    // First create a session
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_004";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_004"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED);
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_004");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test Title");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerForSuper003
 * @tc.desc: Test ProcessControllerForSuper with playback state changed
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerForSuper003, TestSize.Level1)
{
    // First create a session
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_005";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_005"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    // Create mock playback state data
    AVPlaybackState playbackState;
    playbackState.SetState(AVPlaybackState::PLAYBACK_STATE_PLAY);
    playbackState.SetSpeed(1.0);
    AVPlaybackState::Position position;
    position.elapsedTime_ = 1000;
    position.updateTime_ = 2000;
    playbackState.SetPosition(position);
    playbackState.SetBufferedTime(5000);
    
    OHOS::Parcel parcel;
    bool marshallingResult = playbackState.Marshalling(parcel);
    ASSERT_TRUE(marshallingResult) << "AVPlaybackState Marshalling failed";
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    // 1MB limit to prevent memory exhaustion
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED);
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_005");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper001
 * @tc.desc: Test ProcessSessionInfoForSuper with empty sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessSessionInfoForSuper002
 * @tc.desc: Test ProcessSessionInfoForSuper with existing session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper002, TestSize.Level1)
{
    // Create and add existing session
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "existing_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["existing_session"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "existing_session");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper003
 * @tc.desc: Test ProcessSessionInfoForSuper creates new session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper003, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "new_session_001");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.bundle");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_FALSE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.empty());
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper004
 * @tc.desc: Test ProcessSessionInfoForSuper with bundle icon
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper004, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "new_session_002");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.bundle");
    SoftbusSessionUtils::AddStringToJson(jsonValue, BUNDLE_ICON, "test_icon_data");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerInfoForSuper001
 * @tc.desc: Test ProcessControllerInfoForSuper with empty sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerInfoForSuper001, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessControllerInfoForSuper002
 * @tc.desc: Test ProcessControllerInfoForSuper without session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerInfoForSuper002, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "no_session_id");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessControllerInfoForSuper003
 * @tc.desc: Test ProcessControllerInfoForSuper creates controller
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerInfoForSuper003, TestSize.Level1)
{
    // Create session first
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_ctrl";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_ctrl"] = sessionItem;
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_ctrl");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_FALSE(g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.empty());
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper001
 * @tc.desc: Test ProcessMetaDataForSuper with invalid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper001, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "invalid_session");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessMetaDataForSuper002
 * @tc.desc: Test ProcessMetaDataForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper002, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_meta";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_meta"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_meta");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ASSET_ID, "asset_001");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test Song");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "Test Artist");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_LYRIC, "Test Lyric");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_IMAGE, ""); // Empty image
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper001
 * @tc.desc: Test ProcessPlaybackStateForSuper with invalid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper001, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "invalid_session");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackStateForSuper002
 * @tc.desc: Test ProcessPlaybackStateForSuper with empty state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper002, TestSize.Level0)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_state";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_state"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_state");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, "");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper003
 * @tc.desc: Test ProcessPlaybackStateForSuper with valid state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_state2";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_state2"] = sessionItem;
    
    // Create mock playback state
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(255);
    parcel.WriteInt32(-1);
    parcel.WriteInt64(0);
    parcel.WriteInt32(1);
    parcel.WriteCString("");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "test_session_state2");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: SendControlCommandMsgForSuper001
 * @tc.desc: Test SendControlCommandMsgForSuper with empty sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper001, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_PLAY, "");
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: SendControlCommandMsgForSuper002
 * @tc.desc: Test SendControlCommandMsgForSuper with non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper002, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_PLAY, "non_existent_session");
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: SendControlCommandMsgForSuper003
 * @tc.desc: Test SendControlCommandMsgForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_session_cmd";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_session_cmd"] = sessionItem;
    
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_PLAY, "test_session_cmd");
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ColdStartForSuper001
 * @tc.desc: Test ColdStartForSuper without bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper001, TestSize.Level0)
{
    AAFwk::WantParams extras;
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: ColdStartForSuper002
 * @tc.desc: Test ColdStartForSuper with bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper002, TestSize.Level1)
{
    AAFwk::WantParams extras;
    auto stringValue = AAFwk::String::Box("com.test.bundle");
    extras.SetParam(MIGRATE_BUNDLE_NAME, stringValue);
    
    // ColdStartForSuper returns success even if SendByteForNext is not set up
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: CompressFromJPEG001
 * @tc.desc: Test CompressFromJPEG with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG001, TestSize.Level0)
{
    AVMetaData metadata;
    std::vector<uint8_t> inputData;
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: CompressFromJPEG002
 * @tc.desc: Test CompressFromJPEG with invalid data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG002, TestSize.Level1)
{
    AVMetaData metadata;
    std::vector<uint8_t> inputData = {0x00, 0x01, 0x02, 0x03};
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    // Will fail because it's not valid JPEG data
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle001
 * @tc.desc: Test ConvertStateFromDoubleToSingle with PLAY state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle001, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(
        MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    EXPECT_EQ(ret, AVPlaybackState::PLAYBACK_STATE_PLAY);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle002
 * @tc.desc: Test ConvertStateFromDoubleToSingle with PAUSE state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle002, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(
        MEDIA_SESSION_PLAYBACK_STATE_PAUSE);
    EXPECT_EQ(ret, AVPlaybackState::PLAYBACK_STATE_PAUSE);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle003
 * @tc.desc: Test ConvertStateFromDoubleToSingle with STOP state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle003, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(
        MEDIA_SESSION_PLAYBACK_STATE_STOP);
    EXPECT_EQ(ret, AVPlaybackState::PLAYBACK_STATE_STOP);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle004
 * @tc.desc: Test ConvertStateFromDoubleToSingle with ERROR state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle004, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(
        MEDIA_SESSION_PLAYBACK_STATE_ERROR);
    EXPECT_EQ(ret, AVPlaybackState::PLAYBACK_STATE_ERROR);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle005
 * @tc.desc: Test ConvertStateFromDoubleToSingle with unknown state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle005, TestSize.Level0)
{
    int32_t unknownState = 999;
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(unknownState);
    EXPECT_EQ(ret, unknownState);
}

/**
 * @tc.name: IntegrationTest001
 * @tc.desc: Integration test for creating session and controller
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, IntegrationTest001, TestSize.Level1)
{
    // Clean up first
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    // Create JSON for controller list
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON* controllerInfo = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, "integration_test_session");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.integration.test");
    cJSON_AddItemToArray(controllerList, controllerInfo);
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    // Verify session and controller were created
    EXPECT_FALSE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.empty());
    EXPECT_FALSE(g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.empty());
    
    cJSON_Delete(jsonValue);
    
    // Clean up
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: IntegrationTest002
 * @tc.desc: Integration test for metadata and playback state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, IntegrationTest002, TestSize.Level1)
{
    // Setup session
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "integration_meta_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["integration_meta_session"] = sessionItem;
    
    // Test metadata update
    cJSON* metaJson = SoftbusSessionUtils::GetNewCJSONObject();
    SoftbusSessionUtils::AddIntToJson(metaJson, MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_METADATA_CHANNGED);
    SoftbusSessionUtils::AddStringToJson(metaJson, PLAYER_ID, "integration_meta_session");
    SoftbusSessionUtils::AddStringToJson(metaJson, METADATA_TITLE, "Integration Test Song");
    SoftbusSessionUtils::AddStringToJson(metaJson, METADATA_ARTIST, "Integration Test Artist");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(metaJson);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    cJSON_Delete(metaJson);
    
    // Test playback state update
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(255);
    parcel.WriteInt32(-1);
    parcel.WriteInt64(0);
    parcel.WriteInt32(1);
    parcel.WriteCString("");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* stateJson = SoftbusSessionUtils::GetNewCJSONObject();
    SoftbusSessionUtils::AddIntToJson(stateJson, MEDIA_INFO, SYNC_CONTROLLER_CALLBACK_ON_PLAYBACKSTATE_CHANGED);
    SoftbusSessionUtils::AddStringToJson(stateJson, PLAYER_ID, "integration_meta_session");
    SoftbusSessionUtils::AddStringToJson(stateJson, PLAYBACK_STATE, stateEncoded);
    
    ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(stateJson);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    cJSON_Delete(stateJson);
    
    // Clean up
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: MultipleControllers001
 * @tc.desc: Test handling multiple controllers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, MultipleControllers001, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    
    // Add multiple controllers
    for (int i = 0; i < 3; i++) {
        cJSON* controllerInfo = cJSON_CreateObject();
        std::string sessionId = "multi_session_" + std::to_string(i);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, sessionId);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.multi.test");
        cJSON_AddItemToArray(controllerList, controllerInfo);
    }
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), 3);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.size(), 3);
    
    cJSON_Delete(jsonValue);
    
    // Clean up
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

// ==================== ProcessControllerListForSuper Branch Tests ====================

/**
 * @tc.name: ProcessControllerListForSuper003
 * @tc.desc: Test ProcessControllerListForSuper with multiple controllers and metadata
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper003, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    
    // Add controller with full metadata
    cJSON* controllerInfo = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, "session_with_metadata");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.test.full");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, METADATA_ASSET_ID, "asset_full");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, METADATA_TITLE, "Full Title");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, METADATA_ARTIST, "Full Artist");
    cJSON_AddItemToArray(controllerList, controllerInfo);
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerListForSuper004
 * @tc.desc: Test ProcessControllerListForSuper with playback state data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper004, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    // Create playback state data
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PAUSE);
    parcel.WriteInt64(2000);
    parcel.WriteFloat(1.5f);
    parcel.WriteInt64(3000);
    parcel.WriteInt64(10000);
    parcel.WriteInt64(127);
    parcel.WriteInt32(-1);
    parcel.WriteInt64(1);
    parcel.WriteInt32(1);
    parcel.WriteCString("test");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON* controllerInfo = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, "session_with_state");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.test.state");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYBACK_STATE, stateEncoded);
    cJSON_AddItemToArray(controllerList, controllerInfo);
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerListForSuper005
 * @tc.desc: Test ProcessControllerListForSuper with large number of controllers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper005, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    
    // Add 10 controllers
    for (int i = 0; i < 10; i++) {
        cJSON* controllerInfo = cJSON_CreateObject();
        std::string sessionId = "large_session_" + std::to_string(i);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, sessionId);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.large.test");
        cJSON_AddItemToArray(controllerList, controllerInfo);
    }
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), 10);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerListForSuper006
 * @tc.desc: Test ProcessControllerListForSuper with existing sessions and new list
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerListForSuper006, TestSize.Level1)
{
    // Setup existing sessions
    AVSessionDescriptor oldDescriptor;
    oldDescriptor.sessionId_ = "old_session_to_clear";
    OHOS::sptr<AVSessionItem> oldSessionItem = new(std::nothrow) AVSessionItem(oldDescriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["old_session_to_clear"] = oldSessionItem;
    
    OHOS::sptr<AVControllerItem> oldController = new(std::nothrow) AVControllerItem(DEFAULT_NUM, oldSessionItem);
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_["old_session_to_clear"] = oldController;
    
    // Send empty list to clear
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_TRUE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.empty());
    EXPECT_TRUE(g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.empty());
    
    cJSON_Delete(jsonValue);
}

// ==================== ProcessSessionInfoForSuper Branch Tests ====================

/**
 * @tc.name: ProcessSessionInfoForSuper005
 * @tc.desc: Test ProcessSessionInfoForSuper with empty bundle icon
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper005, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_empty_icon");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.emptyicon");
    SoftbusSessionUtils::AddStringToJson(jsonValue, BUNDLE_ICON, ""); // Empty bundle icon
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper006
 * @tc.desc: Test ProcessSessionInfoForSuper with valid bundle icon data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper006, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_valid_icon");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.validicon");
    SoftbusSessionUtils::AddStringToJson(jsonValue, BUNDLE_ICON, "valid_icon_bytes_here");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper007
 * @tc.desc: Test ProcessSessionInfoForSuper with special characters in bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper007, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_special_chars");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.special_chars.bundle");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper008
 * @tc.desc: Test ProcessSessionInfoForSuper with long session ID
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper008, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    std::string longSessionId(256, 'a'); // Very long session ID
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, longSessionId);
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.longid");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessSessionInfoForSuper009
 * @tc.desc: Test ProcessSessionInfoForSuper with duplicate session (already exists)
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessSessionInfoForSuper009, TestSize.Level1)
{
    // First create a session
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "duplicate_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["duplicate_session"] = sessionItem;
    
    size_t originalSize = g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "duplicate_session");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PACKAGE_NAME, "com.test.duplicate");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessSessionInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), originalSize);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

// ==================== ProcessControllerInfoForSuper Branch Tests ====================

/**
 * @tc.name: ProcessControllerInfoForSuper004
 * @tc.desc: Test ProcessControllerInfoForSuper with existing controller
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerInfoForSuper004, TestSize.Level1)
{
    // Create session and controller first
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "existing_ctrl_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["existing_ctrl_session"] = sessionItem;
    
    OHOS::sptr<AVControllerItem> controllerItem = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem);
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_["existing_ctrl_session"] = controllerItem;
    
    size_t originalSize = g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.size();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "existing_ctrl_session");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.size(), originalSize);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessControllerInfoForSuper005
 * @tc.desc: Test ProcessControllerInfoForSuper with session not in stack
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerInfoForSuper005, TestSize.Level0)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "nonexistent_session");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerInfoForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

// ==================== ProcessMetaDataForSuper Branch Tests ====================

/**
 * @tc.name: ProcessMetaDataForSuper003
 * @tc.desc: Test ProcessMetaDataForSuper with only title set
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_only_title";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_only_title"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_only_title");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Only Title Test");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper004
 * @tc.desc: Test ProcessMetaDataForSuper with only artist set
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper004, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_only_artist";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_only_artist"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_only_artist");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "Only Artist Test");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper005
 * @tc.desc: Test ProcessMetaDataForSuper with only lyric set
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper005, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_only_lyric";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_only_lyric"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_only_lyric");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_LYRIC, "Only Lyric Test");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper006
 * @tc.desc: Test ProcessMetaDataForSuper with empty asset ID
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper006, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_empty_asset";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_empty_asset"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_empty_asset");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ASSET_ID, ""); // Empty asset ID
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test with empty asset");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper007
 * @tc.desc: Test ProcessMetaDataForSuper with special characters in metadata
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper007, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_special_meta";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_special_meta"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_special_meta");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Title with 特殊字符 & symbols!@#$%");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "Artist with 日本语 and 中文");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_LYRIC, "Lyric with\nnewline\tand\ttab");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper008
 * @tc.desc: Test ProcessMetaDataForSuper with all empty metadata fields
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper008, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_all_empty";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_all_empty"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_all_empty");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ASSET_ID, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_LYRIC, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_IMAGE, "");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessMetaDataForSuper009
 * @tc.desc: Test ProcessMetaDataForSuper with empty sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper009, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessMetaDataForSuper010
 * @tc.desc: Test ProcessMetaDataForSuper with invalid base64 image data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessMetaDataForSuper010, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_invalid_img";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_invalid_img"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_invalid_img");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test Invalid Image");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_IMAGE, "not_valid_base64!@#$");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    // Should still succeed as image processing failure is logged but not fatal
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

// ==================== ProcessPlaybackStateForSuper Branch Tests ====================

/**
 * @tc.name: ProcessPlaybackStateForSuper004
 * @tc.desc: Test ProcessPlaybackStateForSuper with CALLBACK_INFO field
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper004, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_callback_info";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_callback_info"] = sessionItem;
    
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_STOP);
    parcel.WriteInt64(3000);
    parcel.WriteFloat(2.0f);
    parcel.WriteInt64(4000);
    parcel.WriteInt64(15000);
    parcel.WriteInt64(63);
    parcel.WriteInt32(-1);
    parcel.WriteInt64(2);
    parcel.WriteInt32(1);
    parcel.WriteCString("callback");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_callback_info");
    SoftbusSessionUtils::AddStringToJson(jsonValue, CALLBACK_INFO, stateEncoded);
    // Don't set PLAYBACK_STATE, so CALLBACK_INFO should be used
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper005
 * @tc.desc: Test ProcessPlaybackStateForSuper with PLAYBACK_STATE preferred over CALLBACK_INFO
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper005, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_prefer_playback";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_prefer_playback"] = sessionItem;
    
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(255);
    parcel.WriteInt32(-1);
    parcel.WriteInt64(0);
    parcel.WriteInt32(1);
    parcel.WriteCString("prefer");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_prefer_playback");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    SoftbusSessionUtils::AddStringToJson(jsonValue, CALLBACK_INFO, "should_be_ignored");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper006
 * @tc.desc: Test ProcessPlaybackStateForSuper with actions = 0
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper006, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_zero_actions";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_zero_actions"] = sessionItem;
    
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PAUSE);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(0); // actions = 0
    parcel.WriteInt32(-1);
    parcel.WriteInt64(0);
    parcel.WriteInt32(1);
    parcel.WriteCString("");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_zero_actions");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper007
 * @tc.desc: Test ProcessPlaybackStateForSuper with negative actions
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper007, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_negative_actions";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_negative_actions"] = sessionItem;
    
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_ERROR);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(-1); // negative actions
    parcel.WriteInt32(-1);
    parcel.WriteInt64(0);
    parcel.WriteInt32(1);
    parcel.WriteCString("");
    parcel.WriteInt32(-1);
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_negative_actions");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper008
 * @tc.desc: Test ProcessPlaybackStateForSuper with checkNum mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper008, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_checknum_mismatch";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_checknum_mismatch"] = sessionItem;
    
    OHOS::Parcel parcel;
    parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PLAY);
    parcel.WriteInt64(1000);
    parcel.WriteFloat(1.0f);
    parcel.WriteInt64(2000);
    parcel.WriteInt64(5000);
    parcel.WriteInt64(255);
    parcel.WriteInt32(-2); // Wrong checkNum (should be -1)
    parcel.WriteInt64(0);
    parcel.WriteInt32(0); // Wrong checkNum (should be 1)
    parcel.WriteCString("");
    parcel.WriteInt32(0); // Wrong checkNum (should be -1)
    
    // Safety checks before creating vector
    const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
    size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
    ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
    ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
    ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
    
    std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
    std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_checknum_mismatch");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    // Should still succeed as checkNum mismatches are logged but not fatal
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: ProcessPlaybackStateForSuper009
 * @tc.desc: Test ProcessPlaybackStateForSuper with empty sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper009, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "");
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, "some_data");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessPlaybackStateForSuper010
 * @tc.desc: Test ProcessPlaybackStateForSuper with both PLAYBACK_STATE and CALLBACK_INFO empty
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessPlaybackStateForSuper010, TestSize.Level0)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_both_empty";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_both_empty"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "session_both_empty");
    // Don't set PLAYBACK_STATE or CALLBACK_INFO
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

// ==================== SendControlCommandMsgForSuper Branch Tests ====================

/**
 * @tc.name: SendControlCommandMsgForSuper004
 * @tc.desc: Test SendControlCommandMsgForSuper with PAUSE command
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper004, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_pause_cmd";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_pause_cmd"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_PAUSE, "session_pause_cmd");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: SendControlCommandMsgForSuper005
 * @tc.desc: Test SendControlCommandMsgForSuper with SKIP_TO_NEXT command
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper005, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_next_cmd";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_next_cmd"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_NEXT, "session_next_cmd");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: SendControlCommandMsgForSuper006
 * @tc.desc: Test SendControlCommandMsgForSuper with SKIP_TO_PREVIOUS command
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper006, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_prev_cmd";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_prev_cmd"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_SKIP_TO_PREVIOUS, "session_prev_cmd");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: SendControlCommandMsgForSuper007
 * @tc.desc: Test SendControlCommandMsgForSuper with custom command code
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper007, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_custom_cmd";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_custom_cmd"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        999, "session_custom_cmd");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: SendControlCommandMsgForSuper008
 * @tc.desc: Test SendControlCommandMsgForSuper with special characters in sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, SendControlCommandMsgForSuper008, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "session_special_@#$%";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["session_special_@#$%"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->SendControlCommandMsgForSuper(
        SYNC_MEDIASESSION_CALLBACK_ON_PLAY, "session_special_@#$%");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

// ==================== ColdStartForSuper Branch Tests ====================

/**
 * @tc.name: ColdStartForSuper003
 * @tc.desc: Test ColdStartForSuper with multiple parameters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper003, TestSize.Level1)
{
    AAFwk::WantParams extras;
    auto stringValue = AAFwk::String::Box("com.test.multi");
    extras.SetParam(MIGRATE_BUNDLE_NAME, stringValue);
    auto intValue = AAFwk::Integer::Box(123);
    extras.SetParam("extra_int", intValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    // ColdStartForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ColdStartForSuper004
 * @tc.desc: Test ColdStartForSuper with empty bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper004, TestSize.Level1)
{
    AAFwk::WantParams extras;
    auto stringValue = AAFwk::String::Box("");
    extras.SetParam(MIGRATE_BUNDLE_NAME, stringValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    // ColdStartForSuper returns success even with empty bundle name
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ColdStartForSuper005
 * @tc.desc: Test ColdStartForSuper with special characters in bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper005, TestSize.Level1)
{
    AAFwk::WantParams extras;
    auto stringValue = AAFwk::String::Box("com.test.special_@#$%");
    extras.SetParam(MIGRATE_BUNDLE_NAME, stringValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    // ColdStartForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: ColdStartForSuper006
 * @tc.desc: Test ColdStartForSuper with very long bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ColdStartForSuper006, TestSize.Level1)
{
    AAFwk::WantParams extras;
    std::string longName(512, 'a');
    auto stringValue = AAFwk::String::Box(longName);
    extras.SetParam(MIGRATE_BUNDLE_NAME, stringValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ColdStartForSuper(extras);
    // ColdStartForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

// ==================== CompressFromJPEG Branch Tests ====================

/**
 * @tc.name: CompressFromJPEG003
 * @tc.desc: Test CompressFromJPEG with minimal data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG003, TestSize.Level0)
{
    AVMetaData metadata;
    std::vector<uint8_t> inputData = {0xFF}; // Minimal data
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: CompressFromJPEG004
 * @tc.desc: Test CompressFromJPEG with JPEG header only
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG004, TestSize.Level1)
{
    AVMetaData metadata;
    // JPEG SOI marker
    std::vector<uint8_t> inputData = {0xFF, 0xD8};
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: CompressFromJPEG005
 * @tc.desc: Test CompressFromJPEG with PNG header (wrong format)
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG005, TestSize.Level1)
{
    AVMetaData metadata;
    // PNG header
    std::vector<uint8_t> inputData = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: CompressFromJPEG006
 * @tc.desc: Test CompressFromJPEG with large invalid data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, CompressFromJPEG006, TestSize.Level1)
{
    AVMetaData metadata;
    std::vector<uint8_t> inputData(1024, 0x00); // 1KB of zeros
    int32_t ret = g_migrateAVSessionProxyForSuper->CompressFromJPEG(metadata, inputData);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

// ==================== ConvertStateFromDoubleToSingle Additional Tests ====================

/**
 * @tc.name: ConvertStateFromDoubleToSingle006
 * @tc.desc: Test ConvertStateFromDoubleToSingle with negative state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle006, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(-1);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle007
 * @tc.desc: Test ConvertStateFromDoubleToSingle with large state value
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle007, TestSize.Level0)
{
    int32_t largeState = 10000;
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(largeState);
    EXPECT_EQ(ret, largeState);
}

/**
 * @tc.name: ConvertStateFromDoubleToSingle008
 * @tc.desc: Test ConvertStateFromDoubleToSingle with zero state
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConvertStateFromDoubleToSingle008, TestSize.Level0)
{
    int32_t ret = g_migrateAVSessionProxyForSuper->ConvertStateFromDoubleToSingle(0);
    EXPECT_EQ(ret, 0);
}

// ==================== OnBytesRecvForSuper Additional Tests ====================

/**
 * @tc.name: OnBytesRecvForSuper005
 * @tc.desc: Test OnBytesRecvForSuper with unknown infoType (default branch)
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper005, TestSize.Level0)
{
    std::string deviceId = "test_device";
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    char* jsonStr = cJSON_PrintUnformatted(jsonValue);
    std::string data = std::string(1, (char)MSG_HEAD_MODE_FOR_NEXT) +
                       std::string(1, (char)255) + // Unknown infoType
                       std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

/**
 * @tc.name: OnBytesRecvForSuper006
 * @tc.desc: Test OnBytesRecvForSuper with exactly MSG_HEAD_LENGTH data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper006, TestSize.Level0)
{
    std::string deviceId = "test_device";
    std::string data = "ab"; // Exactly MSG_HEAD_LENGTH (2)
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: OnBytesRecvForSuper007
 * @tc.desc: Test OnBytesRecvForSuper with data length just above MSG_HEAD_LENGTH but invalid JSON
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper007, TestSize.Level0)
{
    std::string deviceId = "test_device";
    std::string data = "abc"; // Just above MSG_HEAD_LENGTH
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: OnBytesRecvForSuper008
 * @tc.desc: Test OnBytesRecvForSuper with SYNC_CONTROLLER type and invalid mediaInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, OnBytesRecvForSuper008, TestSize.Level1)
{
    std::string deviceId = "test_device";
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, -1);
    
    char* jsonStr = cJSON_PrintUnformatted(jsonValue);
    std::string data = std::string(1, (char)MSG_HEAD_MODE_FOR_NEXT) +
                       std::string(1, (char)SYNC_CONTROLLER) +
                       std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonValue);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->OnBytesRecvForSuper(deviceId, data);
    // OnBytesRecvForSuper returns success even if ProcessControllerForSuper fails
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}

// ==================== ProcessControllerForSuper Additional Tests ====================

/**
 * @tc.name: ProcessControllerForSuper004
 * @tc.desc: Test ProcessControllerForSuper with unknown mediaInfo (default branch)
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerForSuper004, TestSize.Level1)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, 999); // Unknown mediaInfo
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: ProcessControllerForSuper005
 * @tc.desc: Test ProcessControllerForSuper with zero mediaInfo
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ProcessControllerForSuper005, TestSize.Level0)
{
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddIntToJson(jsonValue, MEDIA_INFO, 0);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
}

// ==================== Handle Functions Additional Tests ====================

/**
 * @tc.name: HandlePauseForSuper003
 * @tc.desc: Test HandlePauseForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePauseForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_pause_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_pause_session"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePauseForSuper("test_pause_session");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: HandlePlayNextForSuper003
 * @tc.desc: Test HandlePlayNextForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayNextForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_next_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_next_session"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayNextForSuper("test_next_session");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: HandlePlayPreviousForSuper003
 * @tc.desc: Test HandlePlayPreviousForSuper with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, HandlePlayPreviousForSuper003, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "test_prev_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["test_prev_session"] = sessionItem;
    
    int32_t ret = g_migrateAVSessionProxyForSuper->HandlePlayPreviousForSuper("test_prev_session");
    // SendControlCommandMsgForSuper returns success even if SendByteForNext is not set up
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

// ==================== Concurrency and Stress Tests ====================

/**
 * @tc.name: ConcurrentSessionCreation001
 * @tc.desc: Test concurrent session creation
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, ConcurrentSessionCreation001, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    const int numSessions = 5;
    std::vector<std::thread> threads;
    std::mutex mtx;  // 添加互斥锁
    for (int i = 0; i < numSessions; i++) {
        threads.emplace_back([i, &mtx]() {  // 捕获互斥锁引用
            AVSessionDescriptor descriptor;
            descriptor.sessionId_ = "concurrent_session_" + std::to_string(i);
            descriptor.sessionTag_ = "test_tag";
            descriptor.sessionType_ = OHOS::AVSession::AVSession::SESSION_TYPE_AUDIO;
            
            OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
            
            if (sessionItem != nullptr) {
                std::lock_guard<std::mutex> lock(mtx);  // 加锁保护
                g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_[descriptor.sessionId_] = sessionItem;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    std::lock_guard<std::mutex> lock(mtx);  // 加锁保护
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), numSessions);
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: LargeNumberOfControllers001
 * @tc.desc: Test handling large number of controllers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, LargeNumberOfControllers001, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    
    // Add 50 controllers
    for (int i = 0; i < 50; i++) {
        cJSON* controllerInfo = cJSON_CreateObject();
        std::string sessionId = "large_ctrl_session_" + std::to_string(i);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, sessionId);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.large.test");
        cJSON_AddItemToArray(controllerList, controllerInfo);
    }
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    EXPECT_EQ(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), 50);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: RepeatedClearAndRecreate001
 * @tc.desc: Test repeated clear and recreate of sessions
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, RepeatedClearAndRecreate001, TestSize.Level1)
{
    for (int round = 0; round < 5; round++) {
        g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
        g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
        
        cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
        ASSERT_NE(jsonValue, nullptr);
        
        cJSON* controllerList = cJSON_CreateArray();
        cJSON* controllerInfo = cJSON_CreateObject();
        std::string sessionId = "recreate_session_" + std::to_string(round);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, sessionId);
        SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "com.recreate.test");
        cJSON_AddItemToArray(controllerList, controllerInfo);
        cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
        
        int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
        
        cJSON_Delete(jsonValue);
    }
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: MetadataUpdateStress001
 * @tc.desc: Stress test for metadata updates
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, MetadataUpdateStress001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "stress_meta_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["stress_meta_session"] = sessionItem;
    
    // Perform 10 metadata updates
    for (int i = 0; i < 10; i++) {
        cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
        ASSERT_NE(jsonValue, nullptr);
        
        SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "stress_meta_session");
        SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Stress Title " + std::to_string(i));
        SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "Stress Artist " + std::to_string(i));
        
        int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
        
        cJSON_Delete(jsonValue);
    }
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: PlaybackStateUpdateStress001
 * @tc.desc: Stress test for playback state updates
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, PlaybackStateUpdateStress001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "stress_state_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["stress_state_session"] = sessionItem;
    
    // Perform 10 playback state updates
    for (int i = 0; i < 10; i++) {
        OHOS::Parcel parcel;
        parcel.WriteInt32(MEDIA_SESSION_PLAYBACK_STATE_PLAY);
        parcel.WriteInt64(i * 1000);
        parcel.WriteFloat(1.0f);
        parcel.WriteInt64(i * 2000);
        parcel.WriteInt64(i * 5000);
        parcel.WriteInt64(255);
        parcel.WriteInt32(-1);
        parcel.WriteInt64(i);
        parcel.WriteInt32(1);
        parcel.WriteCString("");
        parcel.WriteInt32(-1);
        
        // Safety checks before creating vector
        const uint8_t* parcelData = reinterpret_cast<const uint8_t*>(parcel.GetData());
        size_t parcelSize = static_cast<size_t>(parcel.GetDataSize());
        ASSERT_NE(parcelData, nullptr) << "Parcel data is null";
        ASSERT_GT(parcelSize, 0) << "Parcel data size is zero";
        ASSERT_LT(parcelSize, 1024 * 1024) << "Parcel data size too large";
        
        std::vector<uint8_t> stateVec(parcelData, parcelData + parcelSize);
        std::string stateEncoded = Base64Utils::Base64Encode(stateVec);
        
        cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
        ASSERT_NE(jsonValue, nullptr);
        
        SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "stress_state_session");
        SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYBACK_STATE, stateEncoded);
        
        int32_t ret = g_migrateAVSessionProxyForSuper->ProcessPlaybackStateForSuper(jsonValue);
        EXPECT_EQ(ret, AVSESSION_SUCCESS);
        
        cJSON_Delete(jsonValue);
    }
    
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

// ==================== Edge Cases and Boundary Tests ====================

/**
 * @tc.name: EmptyJsonFields001
 * @tc.desc: Test with all JSON fields empty
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, EmptyJsonFields001, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    cJSON* controllerInfo = cJSON_CreateObject();
    // Add empty fields
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PLAYER_ID, "");
    SoftbusSessionUtils::AddStringToJson(controllerInfo, PACKAGE_NAME, "");
    cJSON_AddItemToArray(controllerList, controllerInfo);
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    // Empty session ID should be skipped
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
}

/**
 * @tc.name: VeryLongStrings001
 * @tc.desc: Test with very long string values
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, VeryLongStrings001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "long_str_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["long_str_session"] = sessionItem;
    
    std::string veryLongString(4096, 'X'); // 4KB string
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "long_str_session");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, veryLongString);
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, veryLongString);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: UnicodeStrings001
 * @tc.desc: Test with unicode strings
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, UnicodeStrings001, TestSize.Level1)
{
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = "unicode_session";
    OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["unicode_session"] = sessionItem;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "unicode_session");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "标题 🎵 🎶");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_ARTIST, "艺术家");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_LYRIC, "歌词\nNew line");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: NullSessionItem001
 * @tc.desc: Test handling when session item becomes null
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, NullSessionItem001, TestSize.Level1)
{
    // Add a null session to the stack
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_["null_session"] = nullptr;
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    SoftbusSessionUtils::AddStringToJson(jsonValue, PLAYER_ID, "null_session");
    SoftbusSessionUtils::AddStringToJson(jsonValue, METADATA_TITLE, "Test");
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessMetaDataForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
}

/**
 * @tc.name: MixedValidInvalidControllers001
 * @tc.desc: Test with mix of valid and invalid controllers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, MixedValidInvalidControllers001, TestSize.Level1)
{
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
    
    cJSON* jsonValue = SoftbusSessionUtils::GetNewCJSONObject();
    ASSERT_NE(jsonValue, nullptr);
    
    cJSON* controllerList = cJSON_CreateArray();
    
    // Valid controller
    cJSON* controllerInfo1 = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo1, PLAYER_ID, "valid_session_1");
    SoftbusSessionUtils::AddStringToJson(controllerInfo1, PACKAGE_NAME, "com.valid.test");
    cJSON_AddItemToArray(controllerList, controllerInfo1);
    
    // Invalid controller (empty ID)
    cJSON* controllerInfo2 = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo2, PLAYER_ID, "");
    SoftbusSessionUtils::AddStringToJson(controllerInfo2, PACKAGE_NAME, "com.invalid.test");
    cJSON_AddItemToArray(controllerList, controllerInfo2);
    
    // Another valid controller
    cJSON* controllerInfo3 = cJSON_CreateObject();
    SoftbusSessionUtils::AddStringToJson(controllerInfo3, PLAYER_ID, "valid_session_2");
    SoftbusSessionUtils::AddStringToJson(controllerInfo3, PACKAGE_NAME, "com.valid.test");
    cJSON_AddItemToArray(controllerList, controllerInfo3);
    
    cJSON_AddItemToObject(jsonValue, MEDIA_CONTROLLER_LIST, controllerList);
    
    int32_t ret = g_migrateAVSessionProxyForSuper->ProcessControllerListForSuper(jsonValue);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    // Should have created 2 valid sessions
    EXPECT_GE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.size(), 2);
    
    cJSON_Delete(jsonValue);
    g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    g_migrateAVSessionProxyForSuper->controllerStackForMigrateIn_.clear();
}

/**
 * @tc.name: RapidSessionCreationAndDestruction001
 * @tc.desc: Test rapid session creation and destruction
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(MigrateAVSessionProxyForSuperTest, RapidSessionCreationAndDestruction001, TestSize.Level1)
{
    for (int i = 0; i < 20; i++) {
        // Create session
        AVSessionDescriptor descriptor;
        descriptor.sessionId_ = "rapid_session_" + std::to_string(i);
        OHOS::sptr<AVSessionItem> sessionItem = new(std::nothrow) AVSessionItem(descriptor);
        g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_[descriptor.sessionId_] = sessionItem;
        
        // Immediately clear
        g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.clear();
    }
    
    EXPECT_TRUE(g_migrateAVSessionProxyForSuper->sessionStackForMigrateIn_.empty());
}