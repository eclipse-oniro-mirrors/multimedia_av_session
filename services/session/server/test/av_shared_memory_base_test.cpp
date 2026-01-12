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
#include <sys/mman.h>

#include "av_shared_memory_base.h"
#include "avsession_errors.h"
#include "avsession_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {

static OHOS::Parcel g_parcel;

class AVSharedMemoryBaseTest : public testing::Test {
public:
   static void SetUpTestCase(void);
   static void TearDownTestCase(void);
   void SetUp();
   void TearDown();
};

void AVSharedMemoryBaseTest::SetUpTestCase()
{
    system("killall com.example.himusicdemo");
    sleep(1);
}

void AVSharedMemoryBaseTest::TearDownTestCase() {}

void AVSharedMemoryBaseTest::SetUp() {}

void AVSharedMemoryBaseTest::TearDown() {}

/**
* @tc.name: Unmarshalling001
* @tc.desc: Unmarshalling
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Unmarshalling001, TestSize.Level0)
{
    SLOGI("Unmarshalling001 Begin");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    OHOS::Parcel& parcel = g_parcel;
    auto unmarshallingPtr = memory->Unmarshalling(parcel);
    EXPECT_EQ(unmarshallingPtr, nullptr);
}

/**
* @tc.name: Unmarshalling002
* @tc.desc: Unmarshalling
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Unmarshalling002, TestSize.Level0)
{
    SLOGI("Unmarshalling002 Begin");
    OHOS::MessageParcel parcel;
    parcel.WriteFileDescriptor(100);
    auto unmarshallingPtr = AVSharedMemoryBase::Unmarshalling(parcel);
    EXPECT_EQ(unmarshallingPtr, nullptr);
}

/**
* @tc.name: Unmarshalling003
* @tc.desc: Unmarshalling
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, Unmarshalling003, TestSize.Level0)
{
    SLOGI("Unmarshalling003 Begin");
    OHOS::MessageParcel parcel;
    parcel.WriteFileDescriptor(100);
    parcel.WriteInt32(10);
    parcel.WriteUint32(1);
    parcel.WriteString("test");
    auto unmarshallingPtr = AVSharedMemoryBase::Unmarshalling(parcel);
    EXPECT_EQ(unmarshallingPtr, nullptr);
}

/**
 * @tc.name: Unmarshalling004
 * @tc.desc: Test Unmarshalling with valid ashmem fd
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Unmarshalling004, TestSize.Level4)
{
    int fd = AshmemCreate("test_ashmem", 4096);
    ASSERT_GT(fd, 0) << "AshmemCreate failed";

    OHOS::MessageParcel parcel;
    parcel.WriteFileDescriptor(fd);
    parcel.WriteInt32(4096);
    parcel.WriteUint32(0);
    parcel.WriteString("test_ashmem");
    auto unmarshallingPtr = AVSharedMemoryBase::Unmarshalling(parcel);
    EXPECT_NE(unmarshallingPtr, nullptr);
    close(fd);
}

/**
 * @tc.name: Unmarshalling005
 * @tc.desc: Test Unmarshalling when ashmem fd size != size in parcel
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Unmarshalling005, TestSize.Level0)
{
    SLOGI("Unmarshalling005 begin!");
    int fd = AshmemCreate("test_ashmem", 4096);
    ASSERT_GT(fd, 0) << "AshmemCreate failed";
    OHOS::MessageParcel parcel;
    parcel.WriteFileDescriptor(fd);
    parcel.WriteInt32(2048);
    parcel.WriteUint32(0);
    parcel.WriteString("test_ashmem");
    auto memory = AVSharedMemoryBase::Unmarshalling(parcel);
    EXPECT_EQ(memory, nullptr);
}

/**
 * @tc.name: Marshalling001
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Marshalling001, TestSize.Level0)
{
    SLOGI("Marshalling001 begin!");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    OHOS::Parcel& parcel = g_parcel;
    memory->fd_ = 1;
    bool ret = memory->Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: WriteToParcel001
* @tc.desc: WriteToParcel
* @tc.type: FUNC
*/
static HWTEST(AVSharedMemoryBaseTest, WriteToParcel001, TestSize.Level0)
{
    SLOGI("WriteToParcel001 Begin");
    int32_t size = 10;
    uint32_t flags = 1;
    const std::string name = "test";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    OHOS::MessageParcel& m_parcel = static_cast<MessageParcel&>(g_parcel);
    memory->fd_ = 1;
    bool ret = memory->WriteToParcel(m_parcel);
    EXPECT_NE(ret, true);
}

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

/**
 * @tc.name: Read007
 * @tc.desc: set position equal to INVALID_POSITION, read valid data from start
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Read007, TestSize.Level4)
{
    SLOGI("Read007 begin!");
    auto memory = std::make_shared<AVSharedMemoryBase>(10, 0, "test");
    ASSERT_NE(memory, nullptr);
    memory->MapMemory(false);
    uint8_t testData = 42;
    memory->Write(&testData, 1, 0);
    uint8_t out = 0;
    int32_t ret = memory->Read(&out, 1, AVSharedMemoryBase::INVALID_POSITION);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: CreateFromLocal_Success
 * @tc.desc: Test CreateFromLocal with valid parameters
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, CreateFromLocal001, TestSize.Level4)
{
    SLOGI("CreateFromLocal001 begin!");

    int32_t size = 4096;
    uint32_t flags = 0;
    const std::string name = "test_ashmem";
    auto memory = AVSharedMemoryBase::CreateFromLocal(size, flags, name);
    ASSERT_NE(memory, nullptr);
    EXPECT_NE(memory, nullptr);
    if (memory != nullptr) {
        EXPECT_EQ(memory->GetSize(), size);
        EXPECT_NE(memory->GetBase(), nullptr);
    }
}

/**
 * @tc.name: CreateFromLocal002
 * @tc.desc: Test CreateFromLocal when Init fails due to invalid size
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, CreateFromLocal002, TestSize.Level0)
{
    SLOGI("CreateFromLocal002 begin!");

    int32_t size = 0;
    uint32_t flags = 0;
    const std::string name = "test_ashmem";
    auto memory = AVSharedMemoryBase::CreateFromLocal(size, flags, name);
    EXPECT_EQ(memory, nullptr);
}

/**
 * @tc.name: CreateFromRemote001
 * @tc.desc: Test CreateFromRemote when ashmem fd size != capacity, triggers Init() failure
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, CreateFromRemote001, TestSize.Level4)
{
    SLOGI("CreateFromRemote001 begin!");
    const int realSize = 4096;
    const std::string ashmem_name = "test_remote_ashmem";
    int fd = AshmemCreate(ashmem_name.c_str(), realSize);
    ASSERT_GT(fd, 0);
    int32_t wrong_size = 2048;
    uint32_t flags = 0;
    const std::string name = "remote_memory";
    auto memory = AVSharedMemoryBase::CreateFromRemote(fd, wrong_size, flags, name);
    EXPECT_EQ(memory, nullptr);
    close(fd);
}

/**
 * @tc.name: Init001
 * @tc.desc: Test Init() when capacity_ <= 0, triggers "size is invalid" log and return error
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Init001, TestSize.Level4)
{
    SLOGI("Init001 begin!");
    int32_t size = 0;
    uint32_t flags = 0;
    const std::string name = "test_invalid_size";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    ASSERT_NE(memory, nullptr);
    int32_t ret = memory->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(ERR_INVALID_PARAM));
    EXPECT_LE(memory->capacity_, 0);
}

/**
 * @tc.name: Init002
 * @tc.desc: Test Init() when fd_ > 0 but ashmem size != capacity_
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Init002, TestSize.Level4)
{
    SLOGI("Init002 begin!");
    int fd = AshmemCreate("test_remote", 4096);
    ASSERT_GT(fd, 0);
    int32_t wrong_size = 2048;
    uint32_t flags = 0;
    const std::string name = "remote_memory";
    auto memory = std::make_shared<AVSharedMemoryBase>(wrong_size, flags, name);
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    EXPECT_GT(memory->fd_, 0);
    int32_t ret = memory->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(ERR_INVALID_PARAM));
    close(fd);
}

/**
 * @tc.name: Init003
 * @tc.desc: Test Init() when fd_ > 0 and ashmem size == capacity_
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Init003, TestSize.Level4)
{
    SLOGI("Init003 begin!");
    int fd = AshmemCreate("test_remote", 4096);
    ASSERT_GT(fd, 0) << "AshmemCreate failed";
    int32_t size = 4096;
    uint32_t flags = 0;
    const std::string name = "remote_memory";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    EXPECT_GT(memory->fd_, 0);
    int32_t ret = memory->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    close(fd);
}

/**
 * @tc.name: Init004
 * @tc.desc: Test Init() when isMapVirAddr=true and mmap fails due to closed fd,
 *           triggers "MapMemory failed" error
 * @tc.type: FUNC
 * @tc.level: Level0
 */
static HWTEST(AVSharedMemoryBaseTest, Init004, TestSize.Level4)
{
    SLOGI("Init004 begin!");
    int fd = AshmemCreate("test_memory", 4096);
    ASSERT_GT(fd, 0) << "AshmemCreate failed";
    close(fd);
    int32_t size = 4096;
    uint32_t flags = 0;
    const std::string name = "closed_fd_memory";
    auto memory = std::make_shared<AVSharedMemoryBase>(size, flags, name);
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    int32_t ret = memory->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(ERR_INVALID_PARAM));
    close(fd);
}

/**
 * @tc.name: Init005
 * @tc.desc: Test Init() when fd_ > 0 and isMapVirAddr=false,
 *           skips MapMemory call (covers false branch of if (isMapVirAddr))
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, Init005, TestSize.Level4)
{
    SLOGI("Init005 begin!");
    const char* ashmemName = "test_ashmem";
    int32_t capacity_ = 4096;
    int fd = AshmemCreate(ashmemName, capacity_);
    ASSERT_GT(fd, 0);
    uint32_t flags = 0;
    const std::string name = "skip_map_memory";
    auto memory = std::make_shared<AVSharedMemoryBase>(capacity_, flags, name);
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    EXPECT_EQ(memory->capacity_, capacity_);
    EXPECT_EQ(memory->fd_, fd);
    int32_t ret = memory->Init(false);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    EXPECT_EQ(memory->base_, nullptr) << "base_ should be null when not mapped";
    close(fd);
}

/**
 * @tc.name: MapMemory001
 * @tc.desc: Test MapMemory when isRemote=false, flags_ has no FLAGS_READ_ONLY,
 *           prot remains PROT_READ | PROT_WRITE
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, MapMemory001, TestSize.Level4)
{
    SLOGI("MapMemory001 begin!");
    int fd = AshmemCreate("test_local", 4096);
    ASSERT_GT(fd, 0);
    auto memory = std::make_shared<AVSharedMemoryBase>(4096, 0, "local_rw");
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    memory->capacity_ = 4096;
    int32_t ret = memory->MapMemory(false);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    EXPECT_NE(memory->base_, nullptr);
    close(fd);
}

/**
 * @tc.name: MapMemory002
 * @tc.desc: Test MapMemory when isRemote=false, flags_ has FLAGS_READ_ONLY,
 *           but isRemote=false so prot remains writeable (short-circuit)
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, MapMemory002, TestSize.Level4)
{
    SLOGI("MapMemory002 begin!");
    int fd = AshmemCreate("test_local_ro", 4096);
    ASSERT_GT(fd, 0);
    auto memory = std::make_shared<AVSharedMemoryBase>(4096,
         AVSharedMemory::FLAGS_READ_ONLY, "local_ro");
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    memory->capacity_ = 4096;
    int32_t ret = memory->MapMemory(false);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    EXPECT_NE(memory->base_, nullptr);
    if (memory->base_ != nullptr) {
        munmap(memory->base_, memory->capacity_);
        memory->base_ = nullptr;
    }
    close(fd);
}

/**
 * @tc.name: MapMemory003
 * @tc.desc: Test MapMemory when isRemote=true, flags_ has no FLAGS_READ_ONLY,
 *           prot remains PROT_READ | PROT_WRITE
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, MapMemory003, TestSize.Level4)
{
    SLOGI("MapMemory003 begin!");
    int fd = AshmemCreate("test_remote", 4096);
    ASSERT_GT(fd, 0);
    auto memory = std::make_shared<AVSharedMemoryBase>(4096, 0, "remote_rw");
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    memory->capacity_ = 4096;
    int32_t ret = memory->MapMemory(true);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    EXPECT_NE(memory->base_, nullptr);
    close(fd);
}

/**
 * @tc.name: MapMemory004
 * @tc.desc: Test MapMemory when isRemote=true, flags_ has FLAGS_READ_ONLY,
 *           prot becomes PROT_READ only
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, MapMemory004, TestSize.Level4)
{
    SLOGI("MapMemory004 begin!");
    int fd = AshmemCreate("test_remote_ro", 4096);
    ASSERT_GT(fd, 0);
    auto memory = std::make_shared<AVSharedMemoryBase>(4096,
        AVSharedMemory::FLAGS_READ_ONLY, "remote_ro");
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    memory->capacity_ = 4096;
    int32_t ret = memory->MapMemory(true);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_SUCCESS));
    EXPECT_NE(memory->base_, nullptr);
    close(fd);
}

/**
 * @tc.name: MapMemory006
 * @tc.desc: Test MapMemory when fd_ is closed, AshmemSetProt fails
 * @tc.type: FUNC
 */
static HWTEST(AVSharedMemoryBaseTest, MapMemory006, TestSize.Level4)
{
    SLOGI("MapMemory006 begin!");
    int fd = AshmemCreate("test_closed", 4096);
    ASSERT_GT(fd, 0);
    auto memory = std::make_shared<AVSharedMemoryBase>(4096, 0, "closed_fd");
    ASSERT_NE(memory, nullptr);
    memory->fd_ = fd;
    memory->capacity_ = 4096;
    close(fd);
    int32_t ret = memory->MapMemory(false);
    EXPECT_EQ(ret, static_cast<int32_t>(AVSESSION_ERROR));
    EXPECT_EQ(memory->base_, nullptr);
}
} //AVSession
} //OHOS