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

#include "avsession_storage_event.h"
#include "avsession_log.h"
#include "avsession_sysevent.h"
#include "avsession_utils.h"
#include <sys/stat.h>
#include <dirent.h>
#include <filesystem>
#include <climits>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <set>

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL

// Returns the on-disk size in bytes of the given file, or 0 on failure.
static int64_t GetFileSizeBytes(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<int64_t>(st.st_size);
}

// Returns current time in milliseconds since epoch.
static int64_t GetCurrentTimestampMs()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

// Formats a millisecond timestamp as "YYYY-MM-DD HH:MM:SS.mmm" in local time.
static std::string FormatTimestamp(int64_t ms)
{
    time_t sec = static_cast<time_t>(ms / 1000);
    int64_t millis = ms % 1000;
    struct tm tmResult {};
    if (localtime_r(&sec, &tmResult) == nullptr) {
        return std::to_string(ms);
    }
    char buf[40] = {0};
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmResult);
    char tail[8] = {0};
    snprintf(tail, sizeof(tail), ".%03lld", static_cast<long long>(millis));
    return std::string(buf) + tail;
}

AVSessionStorageEvent& AVSessionStorageEvent::GetInstance()
{
    static AVSessionStorageEvent instance;
    return instance;
}

AVSessionStorageEvent::AVSessionStorageEvent() : storageUserDataMap_()
{
}

AVSessionStorageEvent::~AVSessionStorageEvent()
{
    SLOGI("AVSessionStorageEvent destruct");
    Uninit();
}

void AVSessionStorageEvent::Init()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    SLOGI("AVSessionStorageEvent init with 24h periodic report");
    StartPeriodicReport();
}

void AVSessionStorageEvent::Uninit()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    SLOGI("AVSessionStorageEvent uninit");
    StopPeriodicReport();
}

void AVSessionStorageEvent::StartPeriodicReport()
{
    auto callback = [this]() {
        std::lock_guard<std::recursive_mutex> lockGuard(lock_);
        SLOGI("Periodic storage statistics report triggered");
        // Re-arm the next cycle BEFORE doing the actual report. This way, even if the
        // report throws or hangs, the timer is already scheduled for the next 24h and
        // won't be permanently lost. AVSessionReplaceTask is non-blocking (just enqueues).
        StartPeriodicReport();
        ReportStorageStatistics();
    };

    if (!AVSessionEventHandler::GetInstance().AVSessionReplaceTask(
        callback, PERIODIC_TASK_NAME, REPORT_INTERVAL_MS)) {
        SLOGE("Failed to start periodic report task");
    }
}

void AVSessionStorageEvent::StopPeriodicReport()
{
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask(PERIODIC_TASK_NAME);
}

void StorageUserData::AddFileInfo(const std::string& fileName, const std::string& bundleName)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    StorageFileInfo info;
    info.bundleName_ = bundleName;
    info.timestamp_ = GetCurrentTimestampMs();
    fileInfoMap_[fileName] = info;  // overwrite if exists, updating timestamp
}

void StorageUserData::RemoveFileInfo(const std::string& fileName)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    fileInfoMap_.erase(fileName);
}

void StorageUserData::ClearFileInfo()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    fileInfoMap_.clear();
}

size_t StorageUserData::GetTotalFileCount()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    return fileInfoMap_.size();
}

int64_t StorageUserData::GetTotalStorageBytes()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    int64_t total = 0;
    for (const auto& pair : fileInfoMap_) {
        total += GetFileSizeBytes(pair.first);
    }
    return total;
}

void StorageUserData::AppendFileInfoStrings(std::vector<std::string>& bundleNames) const
{
    for (const auto& pair : fileInfoMap_) {
        const StorageFileInfo& info = pair.second;
        std::string item = "FILE";
        item += "|TIME=" + FormatTimestamp(info.timestamp_);
        item += "|NAME=" + pair.first;
        item += "|SIZE=" + std::to_string(GetFileSizeBytes(pair.first));
        item += "|BUNDLE=" + info.bundleName_;
        bundleNames.push_back(item);
    }
}

StorageUserData& AVSessionStorageEvent::GetOrCreateStorageUserData(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    auto it = storageUserDataMap_.find(userId);
    if (it == storageUserDataMap_.end()) {
        it = storageUserDataMap_.emplace(userId, std::make_unique<StorageUserData>()).first;
    }
    return *(it->second);
}

void AVSessionStorageEvent::RecordFileWrite(const std::string& fileName,
    const std::string& bundleName, int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    SLOGD("RecordFileWrite: fileName=%{public}s, bundle=%{public}s, user=%{public}d",
        fileName.c_str(), bundleName.c_str(), userId);

    // Only record the file path + bundleName. File size is intentionally NOT stored
    // here — it is stat()ed from disk at report time (in AppendFileInfoStrings and
    // GetTotalStorageBytes) so the reported value always reflects the real on-disk
    // footprint rather than the in-memory buffer size that may differ.
    StorageUserData& userData = GetOrCreateStorageUserData(userId);
    userData.AddFileInfo(fileName, bundleName);

    if (userData.GetTotalFileCount() >= MAX_RECORD_COUNT) {
        SLOGI("Record count reaches %{public}zu, trigger immediate report for user %{public}d",
            MAX_RECORD_COUNT, userId);
        ReportStorageStatisticsForUser(userId);
        // Do NOT reset the global periodic timer here: the 100-record threshold is a
        // per-user emergency flush, while the 24h timer is a shared backstop for all
        // users. Resetting it would silently postpone other users' reports every time
        // this user fills up. The timer keeps its original countdown.
    }
}

void AVSessionStorageEvent::RecordFileDelete(const std::string& fileName, int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    SLOGD("RecordFileDelete: fileName=%{public}s, user=%{public}d", fileName.c_str(), userId);

    auto it = storageUserDataMap_.find(userId);
    if (it == storageUserDataMap_.end()) {
        return;
    }
    it->second->RemoveFileInfo(fileName);
}

void AVSessionStorageEvent::ScanStorageStatistics(int32_t userId, StorageStatistics& stats)
{
    stats = StorageStatistics{};
    const std::string suffix = AVSessionUtils::GetFileSuffix();
    const std::string castPrefix = "cast_";

    // Use std::filesystem to traverse the av_session/ directory tree. This is the same
    // mechanism already used in production (avsession_item.cpp, avsession_service_ext.cpp),
    // so it works under the service's SELinux policy. recursive_directory_iterator covers
    // cache/ and any cast_* subdirectories automatically.
    std::set<std::string> allFiles;
    std::error_code ec;
    std::string rootDir = AVSessionUtils::GetFixedPathName(userId);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(rootDir, ec)) {
        if (ec) {
            continue;
        }
        if (!entry.is_regular_file(ec)) {
            continue;
        }
        allFiles.insert(entry.path().string());
    }

    // Also include in-memory recorded paths as a reliable fallback.
    auto it = storageUserDataMap_.find(userId);
    if (it != storageUserDataMap_.end()) {
        for (const auto& pair : it->second->GetFileInfoMapForScan()) {
            allFiles.insert(pair.first);
        }
    }

    // Classify each unique file by path and name.
    for (const auto& full : allFiles) {
        if (full.find(suffix) == std::string::npos) {
            continue;
        }
        int64_t size = GetFileSizeBytes(full);
        bool inCache = (full.find("/cache/") != std::string::npos);
        size_t slashPos = full.find_last_of('/');
        std::string baseName = (slashPos != std::string::npos) ? full.substr(slashPos + 1) : full;
        bool isCast = (baseName.compare(0, castPrefix.size(), castPrefix) == 0);
        if (inCache && isCast) {
            stats.castCount++;
            stats.castSize += size;
        } else if (inCache) {
            stats.localCount++;
            stats.localSize += size;
        } else {
            stats.historyCount++;
            stats.historySize += size;
        }
        stats.totalCount++;
        stats.totalSize += size;
    }
}

std::vector<int32_t> AVSessionStorageEvent::EnumerateUserIds()
{
    std::vector<int32_t> userIds;
    // /data/service/el2/ is the per-user data root (see AVSessionUtils::DATA_PATH_NAME).
    // public/ is a pseudo-user dir we skip.
    static constexpr const char* EL2_ROOT = "/data/service/el2/";
    static constexpr const char* PUBLIC_DIR = "public";
    DIR* dir = opendir(EL2_ROOT);
    if (dir == nullptr) {
        SLOGW("EnumerateUserIds: opendir failed for %{public}s", EL2_ROOT);
        return userIds;
    }
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        std::string name(entry->d_name);
        if (name == "." || name == ".." || name == PUBLIC_DIR) {
            continue;
        }
        // User ids are numeric directory names.
        char* endPtr = nullptr;
        errno = 0;
        long val = strtol(name.c_str(), &endPtr, 10);
        if (errno != 0 || endPtr == name.c_str() || *endPtr != '\0' || val <= 0 || val > INT_MAX) {
            continue;
        }
        userIds.push_back(static_cast<int32_t>(val));
    }
    closedir(dir);
    return userIds;
}

std::vector<std::string> AVSessionStorageEvent::BuildControlBundleNames(int32_t userId,
    const StorageStatistics& stats)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    std::vector<std::string> bundleNames;

    // Element [0]: aggregated statistics summary.
    // Format: SUMMARY|TOTAL_COUNT=..|TOTAL_SIZE=..|LOCAL_COUNT=..|...|RECORD_COUNT=..|RECORD_SIZE=..
    std::string summary = "SUMMARY";
    summary += "|USER_ID=" + std::to_string(userId);
    summary += "|TOTAL_COUNT=" + std::to_string(stats.totalCount);
    summary += "|TOTAL_SIZE=" + std::to_string(stats.totalSize);
    summary += "|LOCAL_COUNT=" + std::to_string(stats.localCount);
    summary += "|LOCAL_SIZE=" + std::to_string(stats.localSize);
    summary += "|CAST_COUNT=" + std::to_string(stats.castCount);
    summary += "|CAST_SIZE=" + std::to_string(stats.castSize);
    summary += "|HISTORY_COUNT=" + std::to_string(stats.historyCount);
    summary += "|HISTORY_SIZE=" + std::to_string(stats.historySize);
    summary += "|RECORD_COUNT=" + std::to_string(stats.recordCount);
    summary += "|RECORD_SIZE=" + std::to_string(stats.recordSize);
    bundleNames.push_back(summary);

    // Element [1..N]: per-file detail from the in-memory map.
    // Format: FILE|NAME=..|SIZE=..|BUNDLE=..
    auto it = storageUserDataMap_.find(userId);
    if (it != storageUserDataMap_.end()) {
        it->second->AppendFileInfoStrings(bundleNames);
    }

    return bundleNames;
}

void AVSessionStorageEvent::ReportStorageStatistics()
{
    SLOGI("ReportStorageStatistics for all users");
    // Enumerate users from disk so we cover files written by previous versions or before
    // a service restart — not just users that have an in-memory record.
    std::vector<int32_t> diskUsers = EnumerateUserIds();

    // Merge with users that have in-memory records (in case their dir was removed but
    // they still have something to flush from the map).
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    std::set<int32_t> allUsers(diskUsers.begin(), diskUsers.end());
    for (const auto& pair : storageUserDataMap_) {
        allUsers.insert(pair.first);
    }

    for (int32_t userId : allUsers) {
        ReportStorageStatisticsForUser(userId);
    }
}

void AVSessionStorageEvent::ReportStorageStatisticsForUser(int32_t userId, bool clearAfterReport)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    // Build SUMMARY statistics from in-memory file records + disk stat().
    StorageStatistics stats;
    ScanStorageStatistics(userId, stats);

    auto it = storageUserDataMap_.find(userId);
    StorageUserData* userData = (it != storageUserDataMap_.end()) ? it->second.get() : nullptr;

    // Fill in-memory bookkeeping totals so the receiver can distinguish new writes this
    // period (recordCount/recordSize) from total on-disk files (totalCount/totalSize).
    if (userData != nullptr) {
        stats.recordCount = userData->GetTotalFileCount();
        stats.recordSize = userData->GetTotalStorageBytes();
    }

    // Report only when there is something to say: on-disk files OR in-memory records.
    if (stats.totalCount == 0 && stats.recordCount == 0) {
        SLOGD("nothing to report for user %{public}d", userId);
        return;
    }

    std::vector<std::string> controlBundleNames = BuildControlBundleNames(userId, stats);
    if (controlBundleNames.empty()) {
        SLOGW("BuildControlBundleNames failed for user %{public}d", userId);
        return;
    }

    SLOGI("Report storage statistics for user %{public}d: total=%{public}zu files/%{public}lldB, "
        "local=%{public}zu/%{public}lldB, cast=%{public}zu/%{public}lldB, history=%{public}zu/%{public}lldB",
        userId,
        stats.totalCount, static_cast<long long>(stats.totalSize),
        stats.localCount, static_cast<long long>(stats.localSize),
        stats.castCount, static_cast<long long>(stats.castSize),
        stats.historyCount, static_cast<long long>(stats.historySize));

    // Report via the PLAYING_AVSESSION_STATS statistic event. Storage statistics are
    // carried in the AVSESSION_CONTROL_BUNDLE_NAME string array; other fields are left
    // empty as this event is reused purely as the carrier for storage data.
    std::vector<uint8_t> emptyU8;
    std::vector<uint32_t> emptyU32;
    std::vector<uint64_t> emptyU64;
    HISYSEVENT_STATISTIC("PLAYING_AVSESSION_STATS",
        "APP_NAME", "AVSessionStorageEvent",
        "APP_VERSION", "",
        "AVSESSION_STATE", emptyU8,
        "AVSESSION_STATE_TIMESTAMP", emptyU64,
        "AVSESSION_META_QUALITY", emptyU8,
        "AVSESSION_META_QUALITY_TIMESTAMP", emptyU64,
        "AVSESSION_COMMAND_QUALITY", emptyU32,
        "AVSESSION_COMMAND_QUA_TIMESTAMP", emptyU64,
        "AVSESSION_PLAYSTATE", emptyU8,
        "AVSESSION_PLAYSTATE_TIMESTAMP", emptyU64,
        "AVSESSION_CONTROL", emptyU8,
        "AVSESSION_CONTROL_BUNDLE_NAME", controlBundleNames,
        "AVSESSION_CONTROL_TIMESTAMP", emptyU64,
        "APP_TYPE", "storage_stats",
        "SUPPORT_INTENT", "",
        "SUPPORT_AVQUEUE", false);

    // Clear in-memory records only when triggered by the 99-record emergency flush
    // (to bound memory and avoid re-triggering on every subsequent write). The periodic
    // 24h timer deliberately does NOT clear, so it keeps reporting as long as files
    // remain on disk — the in-memory paths also serve as a reliable fallback for the
    // disk scan.
    if (clearAfterReport && userData != nullptr) {
        userData->ClearFileInfo();
    }
}

#endif
} // namespace OHOS::AVSession
