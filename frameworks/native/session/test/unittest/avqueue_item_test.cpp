/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "avmeta_data.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "av_session.h"
#include "avsession_errors.h"
#include "avsession_pixel_map_adapter.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace AVSession {

static OHOS::Parcel g_parcel;

class AVQueueItemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVQueueItemTest::SetUpTestCase()
{}

void AVQueueItemTest::TearDownTestCase()
{}

void AVQueueItemTest::SetUp()
{}

void AVQueueItemTest::TearDown()
{}

/**
* @tc.name: Marshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AVQueueItemTest, Marshalling001, TestSize.Level0)
{
    AVQueueItem avQueueItem;
    OHOS::Parcel& parcel = g_parcel;
    bool ret = avQueueItem.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}
}
}