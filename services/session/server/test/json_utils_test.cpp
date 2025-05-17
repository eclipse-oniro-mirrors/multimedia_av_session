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