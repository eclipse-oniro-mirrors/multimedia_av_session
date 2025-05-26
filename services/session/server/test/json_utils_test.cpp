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
#include "avsession_errors.h"
#include "avsession_log.h"
#include "json_utils.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class JsonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void JsonUtilsTest::SetUpTestCase()
{}

void JsonUtilsTest::TearDownTestCase()
{}

void JsonUtilsTest::SetUp()
{}

void JsonUtilsTest::TearDown()
{}

/**
* @tc.name: IsInt32_001
* @tc.desc: test IsInt32
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsInt32_001, TestSize.Level1)
{
    SLOGI("IsInt32_001 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddNumberToObject(jsonTest, "test", 1);
    bool ret = JsonUtils::IsInt32(jsonTest, "test");
    EXPECT_EQ(ret, true);

    cJSON_Delete(jsonTest);
    SLOGI("IsInt32_001 end!");
}

/**
* @tc.name: IsInt32_002
* @tc.desc: test IsInt32
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsInt32_002, TestSize.Level1)
{
    SLOGI("IsInt32_002 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "test", "1");
    bool ret = JsonUtils::IsInt32(jsonTest, "test");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsInt32_002 end!");
}

/**
* @tc.name: IsString_001
* @tc.desc: test IsString
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsString_001, TestSize.Level1)
{
    SLOGI("IsString_001 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "test", "123");
    bool ret = JsonUtils::IsString(jsonTest, "test");
    EXPECT_EQ(ret, true);

    cJSON_Delete(jsonTest);
    SLOGI("IsString_001 end!");
}

/**
* @tc.name: IsString_002
* @tc.desc: test IsString
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsString_002, TestSize.Level1)
{
    SLOGI("IsString_002 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddNumberToObject(jsonTest, "test", 1);
    bool ret = JsonUtils::IsString(jsonTest, "test");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsString_002 end!");
}

/**
* @tc.name: IsBool_001
* @tc.desc: test IsBool
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsBool_001, TestSize.Level1)
{
    SLOGI("IsBool_001 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddBoolToObject(jsonTest, "test", true);
    bool ret = JsonUtils::IsBool(jsonTest, "test");
    EXPECT_EQ(ret, true);

    cJSON_Delete(jsonTest);
    SLOGI("IsBool_001 end!");
}

/**
* @tc.name: IsBool_002
* @tc.desc: test IsBool
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsBool_002, TestSize.Level1)
{
    SLOGI("IsBool_002 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "test", "123");
    bool ret = JsonUtils::IsBool(jsonTest, "test");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsBool_002 end!");
}

/**
* @tc.name: SetSessionBasicInfo001
* @tc.desc: test SetSessionBasicInfo
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionBasicInfo001, TestSize.Level1)
{
    SLOGI("SetSessionBasicInfo001 begin!");
    std::string jsonStr = R"(
        {"test":1}
    )";
    AVSessionBasicInfo basicInfo;
    int32_t ret = JsonUtils::SetSessionBasicInfo(jsonStr, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionBasicInfo001 end!");
}

/**
* @tc.name: SetSessionDescriptors001
* @tc.desc: test SetSessionDescriptors
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionDescriptors001, TestSize.Level1)
{
    SLOGI("SetSessionDescriptors001 begin!");
    std::string jsonStr = "";
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = JsonUtils::SetSessionDescriptors(jsonStr, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionDescriptors001 end!");
}

/**
* @tc.name: SetSessionDescriptors002
* @tc.desc: test SetSessionDescriptors
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionDescriptors002, TestSize.Level1)
{
    SLOGI("SetSessionDescriptors002 begin!");
    std::string jsonStr = R"(
        {"test":1}
    )";
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = JsonUtils::SetSessionDescriptors(jsonStr, descriptors);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionDescriptors002 end!");
}

/**
* @tc.name: SetSessionDescriptors003
* @tc.desc: test SetSessionDescriptors
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionDescriptors003, TestSize.Level1)
{
    SLOGI("SetSessionDescriptors003 begin!");
    std::string jsonStr = R"(
        {(])}
    )";
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = JsonUtils::SetSessionDescriptors(jsonStr, descriptors);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetSessionDescriptors003 end!");
}

/**
* @tc.name: SetSessionDescriptor001
* @tc.desc: test SetSessionDescriptor
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionDescriptor001, TestSize.Level1)
{
    SLOGI("SetSessionDescriptor001 begin!");
    std::string jsonStr = "";
    AVSessionDescriptor descriptor;
    int32_t ret = JsonUtils::SetSessionDescriptor(jsonStr, descriptor);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionDescriptor001 end!");
}

/**
* @tc.name: SetSessionDescriptor002
* @tc.desc: test SetSessionDescriptor
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionDescriptor002, TestSize.Level1)
{
    SLOGI("SetSessionDescriptor002 begin!");
    std::string jsonStr = R"(
        {(])}
    )";
    AVSessionDescriptor descriptor;
    int32_t ret = JsonUtils::SetSessionDescriptor(jsonStr, descriptor);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("SetSessionDescriptor002 end!");
}

/**
* @tc.name: JsonToVector001
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, JsonToVector001, TestSize.Level1)
{
    SLOGI("JsonToVector001 begin!");
    cJSON* object = nullptr;
    std::vector<int32_t> value;
    int32_t ret = JsonUtils::JsonToVector(object, value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("JsonToVector001 end!");
}

/**
* @tc.name: JsonToVector002
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, JsonToVector002, TestSize.Level1)
{
    SLOGI("JsonToVector002 begin!");
    cJSON* object = cJSON_CreateObject();
    if (object == nullptr) {
        SLOGE("create object fail");
        FAIL();
    }
    cJSON_AddStringToObject(object, "test", "123");
    std::vector<int32_t> value;
    int32_t ret = JsonUtils::JsonToVector(object, value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    cJSON_Delete(object);
    SLOGI("JsonToVector002 end!");
}

/**
* @tc.name: JsonToVector003
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, JsonToVector003, TestSize.Level1)
{
    SLOGI("JsonToVector003 begin!");
    cJSON* array = cJSON_CreateArray();
    if (array == nullptr) {
        SLOGE("create array fail");
        FAIL();
    }
    cJSON* object = cJSON_CreateNumber(123);
    cJSON_AddItemToArray(array, object);
    std::vector<int32_t> value;
    int32_t ret = JsonUtils::JsonToVector(array, value);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    cJSON_Delete(array);
    SLOGI("JsonToVector003 end!");
}

/**
* @tc.name: GetVectorCapability001
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetVectorCapability001, TestSize.Level1)
{
    SLOGI("GetVectorCapability001 begin!");
    std::string sinkCapability = "";
    std::vector<std::vector<int32_t>> value;
    int32_t ret = JsonUtils::GetVectorCapability(sinkCapability, value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetVectorCapability001 end!");
}


/**
* @tc.name: GetVectorCapability002
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetVectorCapability002, TestSize.Level1)
{
    SLOGI("GetVectorCapability002 begin!");
    std::string sinkCapability = R"(
        {(])}
    )";
    std::vector<std::vector<int32_t>> value;
    int32_t ret = JsonUtils::GetVectorCapability(sinkCapability, value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetVectorCapability002 end!");
}

/**
* @tc.name: GetVectorCapability003
* @tc.desc: test GetVectorCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetVectorCapability003, TestSize.Level1)
{
    SLOGI("GetVectorCapability003 begin!");
    std::string sinkCapability = "{ \"key\": \"value\", }";
    std::vector<std::vector<int32_t>> value;
    int32_t ret = JsonUtils::GetVectorCapability(sinkCapability, value);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetVectorCapability003 end!");
}

/**
* @tc.name: IsInt32_003
* @tc.desc: test IsInt32
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsInt32_003, TestSize.Level1)
{
    SLOGI("IsInt32_003 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "TEST", "1");
    bool ret = JsonUtils::IsInt32(jsonTest, "test");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsInt32_003 end!");
}

/**
* @tc.name: IsInt32_004
* @tc.desc: test IsInt32
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsInt32_004, TestSize.Level1)
{
    SLOGI("IsInt32_004 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "test1", "1");
    bool ret = JsonUtils::IsInt32(jsonTest, "test2");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsInt32_004 end!");
}

/**
* @tc.name: IsString_003
* @tc.desc: test IsString
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsString_003, TestSize.Level1)
{
    SLOGI("IsString_003 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddStringToObject(jsonTest, "test1", "123");
    bool ret = JsonUtils::IsString(jsonTest, "test2");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsString_003 end!");
}

/**
* @tc.name: IsBool_003
* @tc.desc: test IsString
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, IsBool_003, TestSize.Level1)
{
    SLOGI("IsBool_003 begin!");

    cJSON* jsonTest = cJSON_CreateObject();
    if (jsonTest == nullptr) {
        SLOGE("create jsontest fail");
        FAIL();
    }
    cJSON_AddBoolToObject(jsonTest, "test1", false);
    bool ret = JsonUtils::IsString(jsonTest, "test2");
    EXPECT_EQ(ret, false);

    cJSON_Delete(jsonTest);
    SLOGI("IsBool_003 end!");
}

/**
* @tc.name: GetAllCapability001
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability001, TestSize.Level1)
{
    SLOGI("GetAllCapability001 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet": {
                "key": "value"
            }
        }
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetAllCapability001 end!");
}

/**
* @tc.name: GetAllCapability002
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability002, TestSize.Level1)
{
    SLOGI("GetAllCapability002 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet": {
                "key": "value"
            }
        }{}
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetAllCapability002 end!");
}

/**
* @tc.name: GetAllCapability003
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability003, TestSize.Level1)
{
    SLOGI("GetAllCapability003 begin!");
    std::string sessionInfoStr = R"({
        "compatibility1": {
            "capabilitySet": {
                "key": "value"
            }
        }
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetAllCapability003 end!");
}

/**
* @tc.name: GetAllCapability004
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability004, TestSize.Level1)
{
    SLOGI("GetAllCapability004 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet1": {
                "key": "value"
            }
        }
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetAllCapability004 end!");
}

/**
* @tc.name: GetAllCapability005
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability005, TestSize.Level1)
{
    SLOGI("GetAllCapability005 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": "invalid_string"
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetAllCapability005 end!");
}

/**
* @tc.name: GetAllCapability006
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability006, TestSize.Level1)
{
    SLOGI("GetAllCapability006 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet": null
        }
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_ERROR);
    SLOGI("GetAllCapability006 end!");
}

/**
* @tc.name: GetAllCapability007
* @tc.desc: test GetAllCapability
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetAllCapability007, TestSize.Level1)
{
    SLOGI("GetAllCapability007 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet": {}
        }
    })";
    std::string outStr;
    int32_t ret = JsonUtils::GetAllCapability(sessionInfoStr, outStr);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetAllCapability007 end!");
}

/**
* @tc.name: SetSessionCapabilitySet001
* @tc.desc: test SetSessionCapabilitySet
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCapabilitySet001, TestSize.Level1)
{
    SLOGI("SetSessionCapabilitySet001 begin!");
    AVSessionBasicInfo basicInfo;
    basicInfo.metaDataCap_ = {1, 2, 3};
    basicInfo.playBackStateCap_ = {1, 2, 3};
    basicInfo.controlCommandCap_ = {1, 2, 3};
    std::string sessionInfoStr = R"({
        "capabilitySet": {}
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCapabilitySet(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCapabilitySet001 end!");
}

/**
* @tc.name: SetSessionCapabilitySet002
* @tc.desc: test SetSessionCapabilitySet
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCapabilitySet002, TestSize.Level1)
{
    SLOGI("SetSessionCapabilitySet002 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "capabilitySet1": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCapabilitySet(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCapabilitySet002 end!");
}

/**
* @tc.name: SetSessionCapabilitySet003
* @tc.desc: test SetSessionCapabilitySet
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCapabilitySet003, TestSize.Level1)
{
    SLOGI("SetSessionCapabilitySet003 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "capabilitySet": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCapabilitySet(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCapabilitySet003 end!");
}

/**
* @tc.name: SetSessionCompatibility001
* @tc.desc: test SetSessionCompatibility
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCompatibility001, TestSize.Level1)
{
    SLOGI("SetSessionCompatibility001 begin!");
    AVSessionBasicInfo basicInfo;
    basicInfo.reserve_ = {1, 2, 3};
    basicInfo.feature_ = {1, 2, 3};
    basicInfo.extendCapability_ = {1, 2, 3};
    std::string sessionInfoStr = R"({
        "compatibility": {}
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCompatibility(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCompatibility001 end!");
}

/**
* @tc.name: SetSessionCompatibility002
* @tc.desc: test SetSessionCompatibility
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCompatibility002, TestSize.Level1)
{
    SLOGI("SetSessionCompatibility002 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "compatibility1": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCompatibility(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCompatibility002 end!");
}

/**
* @tc.name: SetSessionCompatibility003
* @tc.desc: test SetSessionCompatibility
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionCompatibility003, TestSize.Level1)
{
    SLOGI("SetSessionCompatibility003 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "compatibility": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionCompatibility(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionCompatibility003 end!");
}

/**
* @tc.name: SetSessionData001
* @tc.desc: test SetSessionData
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionData001, TestSize.Level1)
{
    SLOGI("SetSessionData001 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "compatibility": {}
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionData(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionData001 end!");
}

/**
* @tc.name: SetSessionData002
* @tc.desc: test SetSessionData
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionData002, TestSize.Level1)
{
    SLOGI("SetSessionData002 begin!");
    AVSessionBasicInfo basicInfo;
    basicInfo.extend_ = {1, 2, 3};
    std::string sessionInfoStr = R"({
        "compatibility1": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionData(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionData002 end!");
}

/**
* @tc.name: SetSessionData003
* @tc.desc: test SetSessionData
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionData003, TestSize.Level1)
{
    SLOGI("SetSessionData003 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "compatibility": {
            "key": "value"
        }
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::SetSessionData(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("SetSessionData003 end!");
}

/**
* @tc.name: SetSessionBasicInfo002
* @tc.desc: test SetSessionBasicInfo
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, SetSessionBasicInfo002, TestSize.Level1)
{
    SLOGI("SetSessionBasicInfo002 begin!");
    std::string sessionInfoStr = R"({
        "compatibility": {
            "capabilitySet": {
                "key": "value"
            }
        }
    }})";
    AVSessionBasicInfo basicInfo;
    int32_t ret = JsonUtils::SetSessionBasicInfo(sessionInfoStr, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("SetSessionBasicInfo002 end!");
}

/**
* @tc.name: GetSessionCapabilitySet001
* @tc.desc: test GetSessionCapabilitySet
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetSessionCapabilitySet001, TestSize.Level1)
{
    SLOGI("GetSessionCapabilitySet001 begin!");
    AVSessionBasicInfo basicInfo;
    std::string sessionInfoStr = R"({
        "metaData": [1, 2, 3],
        "playbackState": [1, 2, 3],
        "controlCommand": [1, 2, 3]
    })";
    cJSON* jsonObj = cJSON_Parse(sessionInfoStr.c_str());
    ASSERT_TRUE(jsonObj != nullptr);
    int32_t ret = JsonUtils::GetSessionCapabilitySet(jsonObj, basicInfo);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(jsonObj);
    SLOGI("GetSessionCapabilitySet001 end!");
}

/**
* @tc.name: GetSessionCompatibility001
* @tc.desc: test GetSessionCompatibility
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetSessionCompatibility001, TestSize.Level1)
{
    SLOGI("GetSessionCompatibility001 begin!");
    const char* jsonStr = R"({
        "networkId": "network123",
        "vendorId": "vendor456",
        "deviceType": "type789",
        "systemVersion": "versionXYZ",
        "avsessionVersion": 1,
        "reserve": ["reserve1", "reserve2"],
        "features": ["feature1", "feature2"],
        "capabilitySet": {
            "metaData": [1, 2, 3],
            "playbackState": [1, 2, 3],
            "controlCommand": [1, 2, 3]
        },
        "extendCapability": ["extend1", "extend2"]
    })";

    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_TRUE(json != nullptr);

    AVSessionBasicInfo basicInfo;
    int32_t ret = JsonUtils::GetSessionCompatibility(json, basicInfo);

    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(json);
    SLOGI("GetSessionCompatibility001 end!");
}


/**
* @tc.name: GetSessionData001
* @tc.desc: test GetSessionData
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetSessionData001, TestSize.Level1)
{
    SLOGI("GetSessionData001 begin!");
    const char* jsonStr = R"({
        "systemTime": 123456789,
        "extend": ["extend1", "extend2"]
    })";

    cJSON* json = cJSON_Parse(jsonStr);
    ASSERT_TRUE(json != nullptr);

    AVSessionBasicInfo basicInfo;
    int32_t ret = JsonUtils::GetSessionData(json, basicInfo);

    EXPECT_EQ(ret, AVSESSION_SUCCESS);

    cJSON_Delete(json);
    SLOGI("GetSessionData001 end!");
}

/**
* @tc.name: GetSessionBasicInfo001
* @tc.desc: test GetSessionBasicInfo
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetSessionBasicInfo001, TestSize.Level1)
{
    SLOGI("GetSessionBasicInfo001 begin!");
    const std::string sessionInfo = R"({
        "compatibility": {
            "networkId": "network123",
            "vendorId": "vendor456",
            "deviceType": "type789",
            "systemVersion": "versionXYZ",
            "avsessionVersion": 1,
            "reserve": ["reserve1", "reserve2"],
            "features": ["feature1", "feature2"],
            "capabilitySet": {
                "metaData": [1, 2, 3],
                "playbackState": [1, 2, 3],
                "controlCommand": [1, 2, 3]
            },
            "extendCapability": ["extend1", "extend2"]
        },
        "data": {
            "systemTime": 123456789,
            "extend": ["extend1", "extend2"]
        }
    })";

    AVSessionBasicInfo basicInfo;
    int32_t ret = JsonUtils::GetSessionBasicInfo(sessionInfo, basicInfo);

    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetSessionBasicInfo001 end!");
}

/**
* @tc.name: GetSessionDescriptors001
* @tc.desc: test GetSessionDescriptors
* @tc.type: FUNC
* @tc.require: #I62OZV
*/
static HWTEST(JsonUtilsTest, GetSessionDescriptors001, TestSize.Level1)
{
    SLOGI("GetSessionDescriptors001 begin!");
    const std::string sessionInfo = R"({
        "data": {
            "sessionDescriptors": [
                {
                    "sessionId": "session1",
                    "type": "audio",
                    "bundleName": "com.example.app1",
                    "abilityName": "MainAbility1",
                    "tag": "tag1",
                    "isThirdPartyApp": true
                },
                {
                    "sessionId": "session2",
                    "type": "video",
                    "bundleName": "com.example.app2",
                    "abilityName": "MainAbility2",
                    "tag": "tag2",
                    "isThirdPartyApp": false
                }
            ]
        }
    })";

    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = JsonUtils::GetSessionDescriptors(sessionInfo, descriptors);

    EXPECT_EQ(ret, AVSESSION_SUCCESS);
    SLOGI("GetSessionDescriptors001 end!");
}
