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
#include <unordered_map>
#include <vector>
#include <string>
#include "hisysevent.h"
#include "avsession_event_handler.h"
#endif

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
struct StorageFileInfo {
    std::string bundleName_;
    int64_t timestamp_ = 0;  // milliseconds since epoch when the file was last written
};

// Aggregated on-disk statistics gathered by scanning AVSession directories.
// Three image categories are tracked:
//   - LOCAL:  av_session/cache/*.image.dat (excluding cast_ prefix)
//   - CAST:   av_session/cache/cast_*.image.dat
//   - HISTORY: av_session/*.image.dat (direct children, not recursing into cache/)
// All size fields are in BYTES (not KB) to avoid integer truncation for small files.
// recordCount/recordSize come from in-memory bookkeeping (writes recorded since the
// last report), so the receiver can distinguish "new writes this period" from "total on disk".
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
    // Records a file write. If the file already exists in the map, its timestamp is
    // updated (overwrite). Timestamp is set automatically to "now".
    void AddFileInfo(const std::string& fileName, const std::string& bundleName);
    void RemoveFileInfo(const std::string& fileName);
    void ClearFileInfo();
    size_t GetTotalFileCount();
    // Appends one serialized string per recorded file to the given vector. File size is
    // obtained from disk (stat) at report time, NOT from the in-memory buffer size, so
    // it reflects the real on-disk footprint. Each string is formatted as
    // "FILE|NAME=..|SIZE=..|BUNDLE=..|TIME=..".
    void AppendFileInfoStrings(std::vector<std::string>& bundleNames) const;
    // Returns total bytes of all recorded files by stat()ing each one on disk.
    int64_t GetTotalStorageBytes();
    // Read-only access to the internal map (for path-based disk scan by AVSessionStorageEvent).
    const std::unordered_map<std::string, StorageFileInfo>& GetFileInfoMapForScan() const
    {
        return fileInfoMap_;
    }

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
    void ReportStorageStatistics();
    void ReportStorageStatisticsForUser(int32_t userId, bool clearAfterReport = true);

private:
    AVSessionStorageEvent();
    ~AVSessionStorageEvent();

    // Returns a reference to the per-user bucket, creating it on demand.
    StorageUserData& GetOrCreateStorageUserData(int32_t userId);
    std::vector<std::string> BuildControlBundleNames(int32_t userId, const StorageStatistics& stats);
    // Scans the AVSession directories for the given user and fills aggregated statistics.
    void ScanStorageStatistics(int32_t userId, StorageStatistics& stats);
    // Enumerates userIds that have an AVSession directory under /data/service/el2/.
    std::vector<int32_t> EnumerateUserIds();
    void StartPeriodicReport();
    void StopPeriodicReport();

    std::unordered_map<int32_t, std::unique_ptr<StorageUserData>> storageUserDataMap_;
    std::recursive_mutex lock_;
    static constexpr uint32_t REPORT_INTERVAL_MS = 24 * 60 * 60 * 1000;
    // The per-user emergency-flush threshold. The reported array is [SUMMARY, file1, ..., fileN]
    // and is carried in AVSESSION_CONTROL_BUNDLE_NAME whose yaml arrsize is 100, so N must be
    // at most 99 to leave room for the SUMMARY entry.
    static constexpr size_t MAX_RECORD_COUNT = 99;
    static constexpr const char* PERIODIC_TASK_NAME = "StorageEventPeriodicReport";
};

// Macros expand directly to AVSessionStorageEvent::GetInstance().XXX(), matching the
// pattern used by HISYSEVENT_REGITER/HISYSEVENT_ADD_OPERATION_COUNT etc. We deliberately
// avoid an inline-function wrapper here: an inline function that is not inlined by the
// compiler generates a real call to a wrapper symbol that itself references GetInstance(),
// and that extra symbol is not exported from the avsession_utils shared library, which
// causes an "undefined symbol" link error in dependent DSOs.
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

#else
#define STORAGE_EVENT_RECORD_FILE_WRITE(fileName, bundleName, userId) \
    do { (void)(fileName); (void)(bundleName); (void)(userId); } while (0)
#define STORAGE_EVENT_RECORD_FILE_DELETE(fileName, userId) \
    do { (void)(fileName); (void)(userId); } while (0)
#define STORAGE_EVENT_INIT() do {} while (0)
#define STORAGE_EVENT_UNINIT() do {} while (0)
#endif

} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_STORAGE_EVENT_H
