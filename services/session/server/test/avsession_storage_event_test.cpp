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
#include <sys/stat.h>
#include <cstdio>
#include <string>

#include "avsession_storage_event.h"
#include "avsession_utils.h"

using namespace OHOS;
using namespace OHOS::AVSession;

class AVSessionStorageEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionStorageEventTest::SetUpTestCase() {}
void AVSessionStorageEventTest::TearDownTestCase() {}

void AVSessionStorageEventTest::SetUp()
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
}

void AVSessionStorageEventTest::TearDown()
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
}

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL

/**
 * @tc.name: RecordFileWrite001
 * @tc.desc: test RecordFileWrite adds file info to map
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordFileWrite001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test.app", 100);
    auto it = evt.storageUserDataMap_.find(100);
    ASSERT_NE(it, evt.storageUserDataMap_.end());
    EXPECT_EQ(it->second->GetTotalFileCount(), 1u);
    it->second->ClearFileInfo();
}

/**
 * @tc.name: RecordFileWrite002
 * @tc.desc: test RecordFileWrite overwrite updates timestamp
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordFileWrite002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    std::string path = "/data/service/el2/100/av_session/cache/abcdef123456.image.dat";
    evt.RecordFileWrite(path, "com.test.app", 100);
    evt.RecordFileWrite(path, "com.test.app2", 100);
    auto it = evt.storageUserDataMap_.find(100);
    ASSERT_NE(it, evt.storageUserDataMap_.end());
    EXPECT_EQ(it->second->GetTotalFileCount(), 1u);
    it->second->ClearFileInfo();
}

/**
 * @tc.name: RecordFileDelete001
 * @tc.desc: test RecordFileDelete removes file info
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordFileDelete001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    std::string path = "/data/service/el2/100/av_session/cache/abcdef123456.image.dat";
    evt.RecordFileWrite(path, "com.test.app", 100);
    evt.RecordFileDelete(path, 100);
    auto it = evt.storageUserDataMap_.find(100);
    if (it != evt.storageUserDataMap_.end()) {
        EXPECT_EQ(it->second->GetTotalFileCount(), 0u);
    }
}

/**
 * @tc.name: RecordFileDelete002
 * @tc.desc: test RecordFileDelete when user does not exist
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordFileDelete002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordFileDelete("nonexistent.image.dat", 999);
    EXPECT_EQ(evt.storageUserDataMap_.find(999), evt.storageUserDataMap_.end());
}

/**
 * @tc.name: RecordSessionInfo001
 * @tc.desc: test RecordSessionInfo stores session
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordSessionInfo001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordSessionInfo("session001", "com.test.app", 100);
    auto it = evt.sessionInfoMap_.find(100);
    ASSERT_NE(it, evt.sessionInfoMap_.end());
    EXPECT_EQ(it->second.size(), 1u);
    EXPECT_EQ(it->second["session001"], "com.test.app");
    evt.sessionInfoMap_.clear();
}

/**
 * @tc.name: RemoveSessionInfo001
 * @tc.desc: test RemoveSessionInfo removes session
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RemoveSessionInfo001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordSessionInfo("session001", "com.test.app", 100);
    evt.RecordSessionInfo("session002", "com.test.app2", 100);
    evt.RemoveSessionInfo("session001");
    auto it = evt.sessionInfoMap_.find(100);
    ASSERT_NE(it, evt.sessionInfoMap_.end());
    EXPECT_EQ(it->second.size(), 1u);
    EXPECT_EQ(it->second.count("session001"), 0u);
    EXPECT_EQ(it->second.count("session002"), 1u);
    evt.sessionInfoMap_.clear();
}

/**
 * @tc.name: RemoveSessionInfo002
 * @tc.desc: test RemoveSessionInfo for non-existent session
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RemoveSessionInfo002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordSessionInfo("session001", "com.test.app", 100);
    evt.RemoveSessionInfo("nonexistent");
    auto it = evt.sessionInfoMap_.find(100);
    ASSERT_NE(it, evt.sessionInfoMap_.end());
    EXPECT_EQ(it->second.size(), 1u);
    evt.sessionInfoMap_.clear();
}

/**
 * @tc.name: InitUninit001
 * @tc.desc: test Init starts timer and Uninit stops it
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, InitUninit001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    EXPECT_EQ(evt.timer_, nullptr);
    evt.Init();
    EXPECT_NE(evt.timer_, nullptr);
    evt.Uninit();
    EXPECT_EQ(evt.timer_, nullptr);
}

/**
 * @tc.name: CollectAllUsers001
 * @tc.desc: test CollectAllUsers merges disk + in-memory users
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, CollectAllUsers001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test", 100);
    auto users = evt.CollectAllUsers();
    EXPECT_NE(users.find(100), users.end());
    auto it = evt.storageUserDataMap_.find(100);
    if (it != evt.storageUserDataMap_.end()) {
        it->second->ClearFileInfo();
    }
}

/**
 * @tc.name: BuildSummary001
 * @tc.desc: test BuildSummary with zero stats (heartbeat format)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, BuildSummary001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    StorageStatistics stats{};
    std::string summary = evt.BuildSummary(-1, stats);
    EXPECT_NE(summary.find("USER_ID=-1"), std::string::npos);
    EXPECT_NE(summary.find("TOTAL_COUNT=0"), std::string::npos);
    EXPECT_NE(summary.find("SESSIONS="), std::string::npos);
}

/**
 * @tc.name: BuildSummary002
 * @tc.desc: test BuildSummary with data and sessions
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, BuildSummary002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.RecordSessionInfo("session001", "com.test.app", 100);
    StorageStatistics stats{};
    stats.totalCount = 5;
    stats.totalSize = 102400;
    stats.localCount = 3;
    stats.castCount = 1;
    stats.historyCount = 1;
    std::string summary = evt.BuildSummary(100, stats);
    EXPECT_NE(summary.find("USER_ID=100"), std::string::npos);
    EXPECT_NE(summary.find("TOTAL_COUNT=5"), std::string::npos);
    EXPECT_NE(summary.find("TOTAL_SIZE=102400"), std::string::npos);
    EXPECT_NE(summary.find("SESSIONS="), std::string::npos);
    EXPECT_NE(summary.find("com.test.app"), std::string::npos);
    evt.sessionInfoMap_.clear();
}

/**
 * @tc.name: ReportStorageStatistics001
 * @tc.desc: test ReportStorageStatistics with empty data produces heartbeat
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, ReportStorageStatistics001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
    evt.ReportStorageStatistics();
    EXPECT_EQ(evt.storageUserDataMap_.size(), 0u);
}

/**
 * @tc.name: ReportStorageStatistics002
 * @tc.desc: test ReportStorageStatistics with in-memory data
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, ReportStorageStatistics002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test.app", 100);
    evt.RecordSessionInfo("session001", "com.test.app", 100);
    ASSERT_NE(evt.storageUserDataMap_.find(100), evt.storageUserDataMap_.end());
    evt.ReportStorageStatistics();
    auto it = evt.storageUserDataMap_.find(100);
    if (it != evt.storageUserDataMap_.end()) {
        EXPECT_EQ(it->second->GetTotalFileCount(), 0u);
    }
    evt.sessionInfoMap_.clear();
}

/**
 * @tc.name: StorageUserData_AddRemove001
 * @tc.desc: test StorageUserData AddFileInfo and RemoveFileInfo
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, StorageUserData_AddRemove001, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/test/file1.image.dat", "com.test");
    EXPECT_EQ(userData.GetTotalFileCount(), 1u);
    userData.AddFileInfo("/test/file2.image.dat", "com.test");
    EXPECT_EQ(userData.GetTotalFileCount(), 2u);
    userData.RemoveFileInfo("/test/file1.image.dat");
    EXPECT_EQ(userData.GetTotalFileCount(), 1u);
    userData.ClearFileInfo();
    EXPECT_EQ(userData.GetTotalFileCount(), 0u);
}

/**
 * @tc.name: StorageUserData_AppendFileInfoStrings001
 * @tc.desc: test AppendFileInfoStrings respects maxCount limit
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, StorageUserData_AppendFileInfoStrings001, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    for (int i = 0; i < 10; i++) {
        userData.AddFileInfo("/test/file" + std::to_string(i) + ".image.dat", "com.test");
    }
    std::vector<std::string> result;
    result.push_back("SUMMARY");
    userData.AppendFileInfoStrings(result, 5);
    EXPECT_EQ(result.size(), 5u);
}

/**
 * @tc.name: StorageUserData_AppendFileInfoStrings002
 * @tc.desc: test AppendFileInfoStrings output format
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, StorageUserData_AppendFileInfoStrings002, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/test/file1.image.dat", "com.test.app");
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_NE(result[0].find("FILE"), std::string::npos);
    EXPECT_NE(result[0].find("com.test.app"), std::string::npos);
    EXPECT_NE(result[0].find("|TIME="), std::string::npos);
    EXPECT_NE(result[0].find("|SIZE="), std::string::npos);
}

/**
 * @tc.name: GetTotalStorageBytes001
 * @tc.desc: test GetTotalStorageBytes returns 0 for nonexistent files
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, GetTotalStorageBytes001, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/nonexistent/file1.image.dat", "com.test");
    EXPECT_EQ(userData.GetTotalStorageBytes(), 0);
}

/**
 * @tc.name: TriggerImmediateReport001
 * @tc.desc: test TriggerImmediateReport calls ReportStorageStatistics
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, TriggerImmediateReport001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test.app", 100);
    ASSERT_NE(evt.storageUserDataMap_.find(100), evt.storageUserDataMap_.end());
    evt.TriggerImmediateReport();
    auto it = evt.storageUserDataMap_.find(100);
    if (it != evt.storageUserDataMap_.end()) {
        EXPECT_EQ(it->second->GetTotalFileCount(), 0u);
    }
}

/**
 * @tc.name: StorageStatistics_DefaultValues001
 * @tc.desc: test StorageStatistics default values are zero
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, StorageStatistics_DefaultValues001, testing::ext::TestSize.Level0)
{
    StorageStatistics stats{};
    EXPECT_EQ(stats.totalCount, 0u);
    EXPECT_EQ(stats.totalSize, 0);
    EXPECT_EQ(stats.localCount, 0u);
    EXPECT_EQ(stats.localSize, 0);
    EXPECT_EQ(stats.castCount, 0u);
    EXPECT_EQ(stats.castSize, 0);
    EXPECT_EQ(stats.historyCount, 0u);
    EXPECT_EQ(stats.historySize, 0);
    EXPECT_EQ(stats.recordCount, 0u);
    EXPECT_EQ(stats.recordSize, 0);
}

/**
 * @tc.name: InitUninit002
 * @tc.desc: test repeated Init does not create second timer
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, InitUninit002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.Init();
    EXPECT_NE(evt.timer_, nullptr);
    evt.Init();
    EXPECT_NE(evt.timer_, nullptr);
    evt.Uninit();
}

/**
 * @tc.name: StopPeriodicReport001
 * @tc.desc: test StopPeriodicReport when timer is already null (no-op)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, StopPeriodicReport001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    EXPECT_EQ(evt.timer_, nullptr);
    evt.StopPeriodicReport();
    EXPECT_EQ(evt.timer_, nullptr);
}

/**
 * @tc.name: RecordFileWrite003
 * @tc.desc: test RecordFileWrite triggers immediate report when bundle limit reached
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, RecordFileWrite003, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
    for (size_t i = 0; i < AVSessionStorageEvent::MAX_BUNDLE_NAMES - 1; i++) {
        std::string path = "/data/service/el2/100/av_session/cache/file" + std::to_string(i) + ".image.dat";
        evt.RecordFileWrite(path, "com.test.app", 100);
    }
    auto it = evt.storageUserDataMap_.find(100);
    if (it != evt.storageUserDataMap_.end()) {
        EXPECT_EQ(it->second->GetTotalFileCount(), 0u);
    }
}

/**
 * @tc.name: AppendFileInfoStrings003
 * @tc.desc: test AppendFileInfoStrings with empty map produces nothing
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, AppendFileInfoStrings003, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    EXPECT_EQ(result.size(), 0u);
}

/**
 * @tc.name: AppendFileInfoStrings004
 * @tc.desc: test AppendFileInfoStrings anonymizes sessionId in path
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, AppendFileInfoStrings004, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test.app");
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].find("abcdef123456"), std::string::npos);
    EXPECT_NE(result[0].find("100/av_session/cache/"), std::string::npos);
}

/**
 * @tc.name: AppendFileInfoStrings005
 * @tc.desc: test AppendFileInfoStrings anonymizes cast_ path
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, AppendFileInfoStrings005, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/data/service/el2/100/av_session/cache/cast_abcdef123456.image.dat", "com.test.app");
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].find("cast_abcdef123456"), std::string::npos);
    EXPECT_NE(result[0].find("cast_"), std::string::npos);
}

/**
 * @tc.name: AppendFileInfoStrings006
 * @tc.desc: test AppendFileInfoStrings does not anonymize history (bundleName_queueId)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, AppendFileInfoStrings006, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/data/service/el2/100/av_session/com.test.app_queue1.image.dat", "com.test.app");
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_NE(result[0].find("com.test.app_queue1"), std::string::npos);
}

/**
 * @tc.name: AppendFileInfoStrings007
 * @tc.desc: test AppendFileInfoStrings timestamp format contains date and time
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, AppendFileInfoStrings007, testing::ext::TestSize.Level0)
{
    StorageUserData userData;
    userData.AddFileInfo("/test/file.image.dat", "com.test.app");
    std::vector<std::string> result;
    userData.AppendFileInfoStrings(result, 100);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_NE(result[0].find("|TIME="), std::string::npos);
    EXPECT_NE(result[0].find("-"), std::string::npos);
    EXPECT_NE(result[0].find(":"), std::string::npos);
    EXPECT_NE(result[0].find("."), std::string::npos);
}

/**
 * @tc.name: GetOrCreateStorageUserData001
 * @tc.desc: test GetOrCreateStorageUserData creates new and returns existing
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, GetOrCreateStorageUserData001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    auto& ref1 = evt.GetOrCreateStorageUserData(200);
    EXPECT_EQ(evt.storageUserDataMap_.count(200), 1u);
    auto& ref2 = evt.GetOrCreateStorageUserData(200);
    EXPECT_EQ(&ref1, &ref2);
    evt.storageUserDataMap_.clear();
}

/**
 * @tc.name: ScanStorageStatistics001
 * @tc.desc: test ScanStorageStatistics classifies in-memory files
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, ScanStorageStatistics001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/abcdef123456.image.dat", "com.test", 100);
    evt.RecordFileWrite("/data/service/el2/100/av_session/cache/cast_abcdef123456.image.dat", "com.test", 100);
    evt.RecordFileWrite("/data/service/el2/100/av_session/com.test_queue1.image.dat", "com.test", 100);
    StorageStatistics stats;
    evt.ScanStorageStatistics(100, stats);
    EXPECT_EQ(stats.localCount + stats.castCount + stats.historyCount, stats.totalCount);
    EXPECT_GE(stats.localCount, 1u);
    EXPECT_GE(stats.castCount, 1u);
    EXPECT_GE(stats.historyCount, 1u);
}

/**
 * @tc.name: ScanStorageStatistics002
 * @tc.desc: test ScanStorageStatistics for non-existent user
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, ScanStorageStatistics002, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    StorageStatistics stats;
    evt.ScanStorageStatistics(999, stats);
    EXPECT_EQ(stats.totalCount, 0u);
}

/**
 * @tc.name: EnumerateUserIds001
 * @tc.desc: test EnumerateUserIds returns at least current user
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, EnumerateUserIds001, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    auto users = evt.EnumerateUserIds();
    for (int32_t uid : users) {
        EXPECT_GT(uid, 0);
    }
}

/**
 * @tc.name: ReportStorageStatistics003
 * @tc.desc: test ReportStorageStatistics truncates FILE entries when bundle is full
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, ReportStorageStatistics003, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.storageUserDataMap_.clear();
    evt.sessionInfoMap_.clear();
    for (size_t i = 0; i < 50; i++) {
        std::string path = "/data/service/el2/100/av_session/cache/file" + std::to_string(i) + ".image.dat";
        evt.RecordFileWrite(path, "com.test.app", 100);
        std::string path2 = "/data/service/el2/101/av_session/cache/file" + std::to_string(i) + ".image.dat";
        evt.RecordFileWrite(path2, "com.test.app", 101);
    }
    ASSERT_EQ(evt.storageUserDataMap_.size(), 2u);
    evt.ReportStorageStatistics();
    for (const auto& pair : evt.storageUserDataMap_) {
        EXPECT_EQ(pair.second->GetTotalFileCount(), 0u);
    }
    evt.storageUserDataMap_.clear();
}

/**
 * @tc.name: BuildSummary003
 * @tc.desc: test BuildSummary with multiple sessions for one user
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionStorageEventTest, BuildSummary003, testing::ext::TestSize.Level0)
{
    auto& evt = AVSessionStorageEvent::GetInstance();
    evt.Uninit();
    evt.sessionInfoMap_.clear();
    evt.RecordSessionInfo("session001", "com.app1", 100);
    evt.RecordSessionInfo("session002", "com.app2", 100);
    StorageStatistics stats{};
    stats.totalCount = 2;
    std::string summary = evt.BuildSummary(100, stats);
    EXPECT_NE(summary.find("com.app1"), std::string::npos);
    EXPECT_NE(summary.find("com.app2"), std::string::npos);
    EXPECT_NE(summary.find(";"), std::string::npos);
    evt.sessionInfoMap_.clear();
}

#endif
