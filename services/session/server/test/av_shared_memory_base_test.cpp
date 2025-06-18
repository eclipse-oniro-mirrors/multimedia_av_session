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
#include <unistd.h>

#include "av_shared_memory_helper.h"
#include "av_shared_memory_base.h"
#include "avsession_errors.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {

class AVSharedMemoryBaseTest : public testing::Test {
public:
   static void SetUpTestCase(void);
   static void TearDownTestCase(void);
   void SetUp();
   void TearDown();
};

void AVSharedMemoryBaseTest::SetUpTestCase() {}

void AVSharedMemoryBaseTest::TearDownTestCase() {}

void AVSharedMemoryBaseTest::SetUp() {}

void AVSharedMemoryBaseTest::TearDown() {}

/**
* @tc.name: Write001
* @tc.desc: set the input array  to nullptr
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write001, TestSize.Level0)
{
    SLOGI("Write001 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = nullptr;
    int32_t writeSize = 0;
    int32_t position = 0;
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, 0);
}

/**
* @tc.name: Write002
* @tc.desc: set writeSize to zero
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write002, TestSize.Level0)
{
    SLOGI("Write002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = new uint8_t [2];
    std::fill_n(in, 1, 2);
    int32_t writeSize = 0;
    int32_t position = 0;
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, 0);
    delete[] in;
}

/**
* @tc.name: Write003
* @tc.desc: set writeSize equal to INVALID_POSITION
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write003, TestSize.Level0)
{
    SLOGI("Write003 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = new uint8_t [2];
    std::fill_n(in, 1, 2);
    int32_t writeSize = 1;
    int32_t position = -1;
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, 0);
    delete[] in;
}

/**
* @tc.name: Write004
* @tc.desc: set writeSize bigger than capacity
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write004, TestSize.Level0)
{
    SLOGI("Write004 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = new uint8_t [2];
    std::fill_n(in, 1, 2);
    int32_t writeSize = 100;
    int32_t position = 0;
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, 0);
    delete[] in;
}

/**
* @tc.name: Write005
* @tc.desc: the base_ of memory is nullptr
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write005, TestSize.Level0)
{
    SLOGI("Write005 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = new uint8_t [2];
    std::fill_n(in, 1, 2);
    int32_t writeSize = 2;
    int32_t position = 0;
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, 0);
    delete[] in;
}

/**
* @tc.name: Write006
* @tc.desc: success to write
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Write006, TestSize.Level0)
{
    SLOGI("Write006 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *in = new uint8_t [2];
    std::fill_n(in, 1, 2);
    int32_t writeSize = 2;
    int32_t position = 0;
    memory->base_ = new uint8_t[size];
    int32_t ret = memory->Write(in, writeSize, position);
    EXPECT_EQ(ret, writeSize);
    delete[] memory->base_;
    delete[] in;
}

/**
* @tc.name: Read001
* @tc.desc: out array is nullptr
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read001, TestSize.Level0)
{
    SLOGI("Read001 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = nullptr;
    int32_t readSize = 2;
    int32_t position = 0;
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 0);
}

/**
* @tc.name: Read002
* @tc.desc: set readSize equal to zero
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read002, TestSize.Level0)
{
    SLOGI("Read002 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = new uint8_t [2];
    std::fill_n(out, 0, 2);
    int32_t readSize = 0;
    int32_t position = 0;
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 0);
    delete[] out;
}

/**
* @tc.name: Read003
* @tc.desc: set position equal to INVALID_POSITION
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read003, TestSize.Level0)
{
    SLOGI("Read003 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = new uint8_t [2];
    std::fill_n(out, 0, 2);
    int32_t readSize = 0;
    int32_t position = -1;
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 0);
    delete[] out;
}

/**
* @tc.name: Read004
* @tc.desc: set length bigger than capacity_
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read004, TestSize.Level0)
{
    SLOGI("Read004 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = new uint8_t [2];
    std::fill_n(out, 0, 2);
    int32_t readSize = 100;
    int32_t position = 0;
    memory->size_ = 100;
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 0);
    delete[] out;
}

/**
* @tc.name: Read005
* @tc.desc: base_ array is nullptr
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read005, TestSize.Level0)
{
    SLOGI("Read005 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = new uint8_t [2];
    std::fill_n(out, 0, 2);
    int32_t readSize = 2;
    int32_t position = 0;
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 0);
    delete[] out;
}

/**
* @tc.name: Read006
* @tc.desc: success to read
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Read006, TestSize.Level0)
{
    SLOGI("Read006 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    uint8_t *out = new uint8_t [3];
    std::fill_n(out, 0, 3);
    int32_t readSize = 2;
    int32_t position = 0;
    memory->size_ = 3;
    memory->base_ = new uint8_t[3];
    std::fill_n(memory->base_, 1, 3);
    int32_t ret = memory->Read(out, readSize, position);
    EXPECT_EQ(ret, 2);
    delete[] memory->base_;
    delete[] out;
}

} //AVSession
} //OHOS