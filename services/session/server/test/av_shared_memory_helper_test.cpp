/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <unistd.h>

#include "av_shared_memory_helper.h"
#include "av_shared_memory_base.h"
#include "avsession_errors.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {

class AVSharedMemoryHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSharedMemoryHelperTest::SetUpTestCase() {}

void AVSharedMemoryHelperTest::TearDownTestCase() {}

void AVSharedMemoryHelperTest::SetUp() {}

void AVSharedMemoryHelperTest::TearDown() {}

/**
* @tc.name: ReadAVSharedMemoryFromParcel001
* @tc.desc: set fd to -1
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, ReadAVSharedMemoryFromParcel001, TestSize.Level1)
{
    SLOGI("ReadAVSharedMemoryFromParcel001 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    memory->fd_ = -1;
    MessageParcel parcel;
    auto ret = ReadAVSharedMemoryFromParcel(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name: ReadAVSharedMemoryFromParcel002
* @tc.desc: set fd to 1
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, ReadAVSharedMemoryFromParcel002, TestSize.Level1)
{
    SLOGI("ReadAVSharedMemoryFromParcel002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    int fd = open("/data/file.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    memory->fd_ = fd;
    MessageParcel parcel;
    auto ret = ReadAVSharedMemoryFromParcel(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name: ReadAVDataSrcMemoryFromParcel001
* @tc.desc: set fd to -1
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, ReadAVDataSrcMemoryFromParcel001, TestSize.Level1)
{
    SLOGI("WriteAVSharedMemoryToParcel002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    memory->fd_ = -1;
    MessageParcel parcel;
    auto ret = ReadAVDataSrcMemoryFromParcel(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name: ReadAVDataSrcMemoryFromParcel002
* @tc.desc: set fd to 1
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, ReadAVDataSrcMemoryFromParcel002, TestSize.Level1)
{
    SLOGI("ReadAVDataSrcMemoryFromParcel002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    int fd = open("/data/file.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    memory->fd_ = fd;
    MessageParcel parcel;
    auto ret = ReadAVDataSrcMemoryFromParcel(parcel);
    EXPECT_EQ(ret, nullptr);
}

/**
* @tc.name: WriteAVSharedMemoryToParcel001
* @tc.desc: set memory to nullptr
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, WriteAVSharedMemoryToParcel001, TestSize.Level1)
{
    SLOGI("WriteAVSharedMemoryToParcel001 begin!");
    std::shared_ptr<AVSharedMemory> memory = nullptr;
    MessageParcel parcel;
    int32_t ret = WriteAVSharedMemoryToParcel(memory, parcel);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
 * @tc.name: WriteAVSharedMemoryToParcel002
 * @tc.desc: set fd to -1
 * @tc.type: FUNC
 */
HWTEST_F(AVSharedMemoryHelperTest, WriteAVSharedMemoryToParcel002, TestSize.Level1)
{
    SLOGI("WriteAVSharedMemoryToParcel002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    MessageParcel parcel;
    int32_t ret = WriteAVSharedMemoryToParcel(memory, parcel);
    EXPECT_EQ(ret, AVSESSION_ERROR);
}

/**
* @tc.name: WriteAVSharedMemoryToParcel003
* @tc.desc: success to write
* @tc.type: FUNC
*/
HWTEST_F(AVSharedMemoryHelperTest, WriteAVSharedMemoryToParcel003, TestSize.Level1)
{
    SLOGI("WriteAVSharedMemoryToParcel003 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    int fd = open("/data/file.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    memory->fd_ = fd;
    MessageParcel parcel;
    int32_t ret = WriteAVSharedMemoryToParcel(memory, parcel);
    EXPECT_EQ(ret, AVSESSION_SUCCESS);
}
} //AVSession
} //OHOS