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
#include "directory_ex.h"
#include <sys/stat.h>
#include <dirent.h>
#include <climits>
#include <cerrno>
#include <cstdlib>
#include <set>

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL

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

void StorageUserData::AddFileInfo(const std::string& fileName, int64_t fileSizeKB, const std::string& bundleName)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    StorageFileInfo info;
    info.fileSizeKB_ = fileSizeKB;
    info.bundleName_ = bundleName;
    fileInfoMap_[fileName] = info;
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

int64_t StorageUserData::GetTotalStorageKB()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    int64_t total = 0;
    for (const auto& pair : fileInfoMap_) {
        total += pair.second.fileSizeKB_;
    }
    return total;
}

void StorageUserData::AppendFileInfoStrings(std::vector<std::string>& bundleNames) const
{
    for (const auto& pair : fileInfoMap_) {
        const StorageFileInfo& info = pair.second;
        std::string item = "FILE";
        item += "|NAME=" + pair.first;
        item += "|SIZE=" + std::to_string(info.fileSizeKB_);
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

int64_t AVSessionStorageEvent::BytesToKB(int64_t bytes)
{
    constexpr int64_t KB_FACTOR = 1024;
    return (bytes > 0) ? (bytes / KB_FACTOR) : 0;
}

void AVSessionStorageEvent::RecordFileWrite(const std::string& fileName, int64_t fileSizeBytes,
    const std::string& bundleName, int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    SLOGD("RecordFileWrite: fileName=%{public}s, size=%{public}lld bytes, bundle=%{public}s, user=%{public}d",
        fileName.c_str(), static_cast<long long>(fileSizeBytes), bundleName.c_str(), userId);

    StorageUserData& userData = GetOrCreateStorageUserData(userId);
    int64_t fileSizeKB = BytesToKB(fileSizeBytes);

    userData.AddFileInfo(fileName, fileSizeKB, bundleName);

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

    // Helper: get file size in bytes, return 0 on failure.
    auto fileSizeBytes = [](const std::string& path) -> int64_t {
        struct stat st {};
        if (stat(path.c_str(), &st) != 0) {
            return 0;
        }
        return static_cast<int64_t>(st.st_size);
    };

    // 1. Scan cache/ directory for LOCAL and CAST images.
    std::string cacheDir = AVSessionUtils::GetCachePathName(userId);
    std::vector<std::string> cacheFiles;
    GetDirFiles(cacheDir, cacheFiles);
    const std::string castPrefix = "cast_";
    for (const auto& file : cacheFiles) {
        if (file.find(suffix) == std::string::npos) {
            continue;
        }
        // Extract the base file name to check the cast_ prefix.
        size_t pos = file.find_last_of('/');
        std::string baseName = (pos != std::string::npos) ? file.substr(pos + 1) : file;
        int64_t sizeKB = BytesToKB(fileSizeBytes(file));
        if (baseName.compare(0, castPrefix.size(), castPrefix) == 0) {
            stats.castCount++;
            stats.castSizeKB += sizeKB;
        } else {
            stats.localCount++;
            stats.localSizeKB += sizeKB;
        }
        stats.totalCount++;
        stats.totalSizeKB += sizeKB;
    }

    // 2. Scan av_session/ direct children for HISTORY images (non-recursive into cache/).
    std::string fixedDir = AVSessionUtils::GetFixedPathName(userId);
    DIR* dir = opendir(fixedDir.c_str());
    if (dir == nullptr) {
        SLOGW("ScanStorageStatistics: opendir failed for %{public}s", fixedDir.c_str());
        return;
    }
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        // Only regular files (skip ".", "..", and subdirectories like cache/).
        if (entry->d_type != DT_REG) {
            continue;
        }
        std::string name(entry->d_name);
        if (name.find(suffix) == std::string::npos) {
            continue;
        }
        std::string full = fixedDir + name;
        int64_t sizeKB = BytesToKB(fileSizeBytes(full));
        stats.historyCount++;
        stats.historySizeKB += sizeKB;
        stats.totalCount++;
        stats.totalSizeKB += sizeKB;
    }
    closedir(dir);
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
    summary += "|TOTAL_SIZE=" + std::to_string(stats.totalSizeKB);
    summary += "|LOCAL_COUNT=" + std::to_string(stats.localCount);
    summary += "|LOCAL_SIZE=" + std::to_string(stats.localSizeKB);
    summary += "|CAST_COUNT=" + std::to_string(stats.castCount);
    summary += "|CAST_SIZE=" + std::to_string(stats.castSizeKB);
    summary += "|HISTORY_COUNT=" + std::to_string(stats.historyCount);
    summary += "|HISTORY_SIZE=" + std::to_string(stats.historySizeKB);
    summary += "|RECORD_COUNT=" + std::to_string(stats.recordCount);
    summary += "|RECORD_SIZE=" + std::to_string(stats.recordSizeKB);
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

void AVSessionStorageEvent::ReportStorageStatisticsForUser(int32_t userId)
{
    // Scan on-disk directories first so we report even when no in-memory record exists
    // (covers files written before this feature, or after a service restart).
    StorageStatistics stats;
    ScanStorageStatistics(userId, stats);

    auto it = storageUserDataMap_.find(userId);
    StorageUserData* userData = (it != storageUserDataMap_.end()) ? it->second.get() : nullptr;

    // Fill in-memory bookkeeping totals so the receiver can distinguish new writes this
    // period (recordCount/recordSizeKB) from total on-disk files (totalCount/totalSizeKB).
    if (userData != nullptr) {
        stats.recordCount = userData->GetTotalFileCount();
        stats.recordSizeKB = userData->GetTotalStorageKB();
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

    SLOGI("Report storage statistics for user %{public}d: total=%{public}zu files/%{public}lldKB, "
        "local=%{public}zu/%{public}lldKB, cast=%{public}zu/%{public}lldKB, history=%{public}zu/%{public}lldKB",
        userId,
        stats.totalCount, static_cast<long long>(stats.totalSizeKB),
        stats.localCount, static_cast<long long>(stats.localSizeKB),
        stats.castCount, static_cast<long long>(stats.castSizeKB),
        stats.historyCount, static_cast<long long>(stats.historySizeKB));

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

    if (userData != nullptr) {
        userData->ClearFileInfo();
    }
}

#endif
} // namespace OHOS::AVSession
