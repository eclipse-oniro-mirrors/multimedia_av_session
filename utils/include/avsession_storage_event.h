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

#ifndef OHOS_AVSESSION_STORAGE_EVENT_H
#define OHOS_AVSESSION_STORAGE_EVENT_H

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#include <chrono>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>
#include <string>
#include "hisysevent.h"
#include "timer.h"
#endif

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
struct StorageFileInfo {
    std::string bundleName_;
    int64_t timestamp_ = 0;  // milliseconds since epoch
};

struct StorageStatistics {
    size_t totalCount = 0;
    int64_t totalSize = 0;
    size_t localCount = 0;
    int64_t localSize = 0;
    size_t castCount = 0;
    int64_t castSize = 0;
    size_t historyCount = 0;
    int64_t historySize = 0;
    size_t recordCount = 0;
    int64_t recordSize = 0;
};

class StorageUserData {
public:
    void AddFileInfo(const std::string& fileName, const std::string& bundleName);
    void RemoveFileInfo(const std::string& fileName);
    void ClearFileInfo();
    size_t GetTotalFileCount();
    int64_t GetTotalStorageBytes();
    void AppendFileInfoStrings(std::vector<std::string>& bundleNames, size_t maxCount) const;
    const std::unordered_map<std::string, StorageFileInfo>& GetFileInfoMapForScan() const { return fileInfoMap_; }

private:
    std::unordered_map<std::string, StorageFileInfo> fileInfoMap_;
    std::recursive_mutex lock_;
};

class AVSessionStorageEvent {
public:
    static AVSessionStorageEvent& GetInstance();

    void Init();
    void Uninit();

    void RecordFileWrite(const std::string& fileName, const std::string& bundleName, int32_t userId);
    void RecordFileDelete(const std::string& fileName, int32_t userId);
    void RecordSessionInfo(const std::string& sessionId, const std::string& bundleName, int32_t userId);
    void RemoveSessionInfo(const std::string& sessionId);
    void ReportStorageStatistics();
    void TriggerImmediateReport();

private:
    AVSessionStorageEvent();
    ~AVSessionStorageEvent();

    StorageUserData& GetOrCreateStorageUserData(int32_t userId);
    void ScanStorageStatistics(int32_t userId, StorageStatistics& stats);
    std::vector<int32_t> EnumerateUserIds();
    void StartPeriodicReport();
    void StopPeriodicReport();
    std::set<int32_t> CollectAllUsers();
    std::string BuildSummary(int32_t userId, const StorageStatistics& stats);
    void EmitStorageEvent(const std::vector<std::string>& bundleNames);

    std::unordered_map<int32_t, std::unique_ptr<StorageUserData>> storageUserDataMap_;
    std::unordered_map<int32_t, std::unordered_map<std::string, std::string>> sessionInfoMap_;
    std::recursive_mutex lock_;
    std::unique_ptr<Utils::Timer> timer_;
    uint32_t timerId_ = 0;
    static constexpr uint32_t REPORT_INTERVAL_MS = 24 * 60 * 60 * 1000;
    static constexpr size_t MAX_BUNDLE_NAMES = 100;
};

#define STORAGE_EVENT_RECORD_FILE_WRITE(fileName, bundleName, userId)                              \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().RecordFileWrite(                     \
            fileName, bundleName, userId);                                                         \
    } while (0)

#define STORAGE_EVENT_RECORD_FILE_DELETE(fileName, userId)                                         \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().RecordFileDelete(fileName, userId);  \
    } while (0)

#define STORAGE_EVENT_INIT()                                                                       \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().Init();                              \
    } while (0)

#define STORAGE_EVENT_UNINIT()                                                                     \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().Uninit();                            \
    } while (0)

#define STORAGE_EVENT_RECORD_SESSION(sessionId, bundleName, userId)                                \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().RecordSessionInfo(                   \
            sessionId, bundleName, userId);                                                        \
    } while (0)

#define STORAGE_EVENT_REMOVE_SESSION(sessionId)                                                    \
    do {                                                                                           \
        OHOS::AVSession::AVSessionStorageEvent::GetInstance().RemoveSessionInfo(sessionId);        \
    } while (0)

#else
#define STORAGE_EVENT_RECORD_FILE_WRITE(fileName, bundleName, userId) \
    do { (void)(fileName); (void)(bundleName); (void)(userId); } while (0)
#define STORAGE_EVENT_RECORD_FILE_DELETE(fileName, userId) \
    do { (void)(fileName); (void)(userId); } while (0)
#define STORAGE_EVENT_INIT() do {} while (0)
#define STORAGE_EVENT_UNINIT() do {} while (0)
#define STORAGE_EVENT_RECORD_SESSION(sessionId, bundleName, userId) \
    do { (void)(sessionId); (void)(bundleName); (void)(userId); } while (0)
#define STORAGE_EVENT_REMOVE_SESSION(sessionId) \
    do { (void)(sessionId); } while (0)
#endif

} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_STORAGE_EVENT_H
