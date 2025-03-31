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
#include <utility>

#include "avsession_dynamic_loader.h"

using namespace OHOS;
using namespace OHOS::AVSession;

#define AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH  "libavsession_dynamic_insight.z.so"

class AVSessionDynamicLoaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionDynamicLoaderTest::SetUpTestCase()
{}

void AVSessionDynamicLoaderTest::TearDownTestCase()
{}

void AVSessionDynamicLoaderTest::SetUp()
{}

void AVSessionDynamicLoaderTest::TearDown()
{}

/**
* @tc.name: GetFuntion001
* @tc.desc: test GetFuntion
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionDynamicLoaderTest, GetFuntion001, testing::ext::TestSize.Level1)
{
    AVSessionDynamicLoader avsessionDynamicLoader;
    avsessionDynamicLoader.OpenDynamicHandle(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH);
    auto ptr = avsessionDynamicLoader.GetFuntion(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "aaa");
    EXPECT_EQ(ptr, nullptr);
}

/**
* @tc.name: GetFuntion002
* @tc.desc: test GetFuntion
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionDynamicLoaderTest, GetFuntion002, testing::ext::TestSize.Level1)
{
    AVSessionDynamicLoader avsessionDynamicLoader;
    void* dataAddr = malloc(10);
    avsessionDynamicLoader.dynamicLibHandle_.insert(std::make_pair(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, dataAddr));
    avsessionDynamicLoader.OpenDynamicHandle(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH);
    auto ptr = avsessionDynamicLoader.GetFuntion(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "aaa");
    EXPECT_EQ(ptr, nullptr);
    int* intArray = static_cast<int*>(dataAddr);
    delete[] intArray;
}

/**
* @tc.name: CloseDynamicHandle001
* @tc.desc: test CloseDynamicHandle
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionDynamicLoaderTest, CloseDynamicHandle001, testing::ext::TestSize.Level1)
{
    AVSessionDynamicLoader avsessionDynamicLoader;
    void* dataAddr = malloc(10);
    avsessionDynamicLoader.dynamicLibHandle_.insert(std::make_pair(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, dataAddr));
    avsessionDynamicLoader.CloseDynamicHandle(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH);
    auto ptr = avsessionDynamicLoader.GetFuntion(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "aaa");
    EXPECT_EQ(ptr, nullptr);
    int* intArray = static_cast<int*>(dataAddr);
    delete[] intArray;
}

/**
* @tc.name: CloseDynamicHandle002
* @tc.desc: test CloseDynamicHandle
* @tc.type: FUNC
* @tc.require:
*/
static HWTEST_F(AVSessionDynamicLoaderTest, CloseDynamicHandle002, testing::ext::TestSize.Level1)
{
    AVSessionDynamicLoader avsessionDynamicLoader;
    avsessionDynamicLoader.dynamicLibHandle_.insert(std::make_pair(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, nullptr));
    avsessionDynamicLoader.CloseDynamicHandle(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH);
    auto ptr = avsessionDynamicLoader.GetFuntion(AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "aaa");
    EXPECT_EQ(ptr, nullptr);
}
