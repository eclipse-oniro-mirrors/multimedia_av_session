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
    if (timer_ != nullptr) {
        return;
    }
    // Use OHOS::Utils::Timer (a native thread timer) instead of AVSessionEventHandler,
    // because the EventHandler's EventRunner thread may be suspended when the screen is
    // locked, causing the 24h callback to be missed. Utils::Timer runs its own thread
    // and is not affected by screen state.
    timer_ = std::make_unique<Utils::Timer>("StorageEventTimer");
    Utils::Timer::TimerCallback timerCallback = [this]() {
        SLOGI("Periodic storage statistics report triggered");
        ReportStorageStatistics();
    };
    // Third arg = false means periodic (same convention as AVSessionSysEvent::Regiter).
    timerId_ = timer_->Register(timerCallback, REPORT_INTERVAL_MS, false);
    timer_->Setup();
}

void AVSessionStorageEvent::StopPeriodicReport()
{
    if (timer_ != nullptr) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
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

void StorageUserData::AppendFileInfoStrings(std::vector<std::string>& bundleNames, size_t maxCount) const
{
    for (const auto& pair : fileInfoMap_) {
        if (bundleNames.size() >= maxCount) {
            break;
        }
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

    // Check if the total bundle size (SUMMARY entries per user + FILE entries across all
    // users) would exceed MAX_BUNDLE_NAMES. Each user contributes 1 SUMMARY + N FILEs.
    // When the limit is reached, trigger an immediate report and clear all maps.
    size_t totalFileRecords = 0;
    for (const auto& pair : storageUserDataMap_) {
        totalFileRecords += pair.second->GetTotalFileCount();
    }
    size_t summaryCount = storageUserDataMap_.size();
    if (summaryCount + totalFileRecords >= MAX_BUNDLE_NAMES) {
        SLOGI("Bundle size reaches %{public}zu (summary=%{public}zu + files=%{public}zu), "
            "trigger immediate report", summaryCount + totalFileRecords, summaryCount, totalFileRecords);
        // TriggerImmediateReport reports all users in a single event and clears all maps.
        TriggerImmediateReport();
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

    // Collect file paths from two sources and de-duplicate via a set:
    //   1. Directory scan via GetDirFiles — covers upgrade-leftover files and files
    //      written before the current service run. Requires SELinux read permission on
    //      the directory (data_service_el2_file:dir { read } in av_session.te).
    //   2. In-memory recorded paths — reliable fallback for files written this session.
    std::set<std::string> allFiles;

    // Scan both cache/ and av_session/ separately to maximize coverage.
    std::vector<std::string> cacheFiles;
    OHOS::GetDirFiles(AVSessionUtils::GetCachePathName(userId), cacheFiles);
    std::vector<std::string> fixedFiles;
    OHOS::GetDirFiles(AVSessionUtils::GetFixedPathName(userId), fixedFiles);
    SLOGI("ScanStorageStatistics: userId=%{public}d, cacheDir=%{public}s found=%{public}zu, "
        "fixedDir=%{public}s found=%{public}zu",
        userId, AVSessionUtils::GetCachePathName(userId).c_str(), cacheFiles.size(),
        AVSessionUtils::GetFixedPathName(userId).c_str(), fixedFiles.size());
    for (const auto& f : cacheFiles) {
        allFiles.insert(f);
    }
    for (const auto& f : fixedFiles) {
        allFiles.insert(f);
    }

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

void AVSessionStorageEvent::ReportStorageStatistics()
{
    SLOGI("ReportStorageStatistics for all users in a single event");
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    // Enumerate users from disk (covers files written before this feature / by previous
    // runs) and merge with users that have in-memory records.
    std::vector<int32_t> diskUsers = EnumerateUserIds();
    std::set<int32_t> allUsers(diskUsers.begin(), diskUsers.end());
    for (const auto& pair : storageUserDataMap_) {
        allUsers.insert(pair.first);
    }

    // Build SUMMARY + FILE entries into a single AVSESSION_CONTROL_BUNDLE_NAME array.
    // SUMMARY entries (one per user) are added first; FILE entries fill the remaining
    // slots up to MAX_BUNDLE_NAMES. This guarantees that when the total would exceed the
    // yaml arrsize limit, every user's SUMMARY is still emitted while FILE detail is
    // truncated.
    std::vector<std::string> bundleNames;

    // First pass: compute stats for each user and emit SUMMARY entries.
    struct PerUserData {
        int32_t userId;
        StorageStatistics stats;
        StorageUserData* userData;
    };
    std::vector<PerUserData> perUser;
    for (int32_t userId : allUsers) {
        PerUserData pud;
        pud.userId = userId;
        ScanStorageStatistics(userId, pud.stats);

        auto it = storageUserDataMap_.find(userId);
        pud.userData = (it != storageUserDataMap_.end()) ? it->second.get() : nullptr;
        if (pud.userData != nullptr) {
            pud.stats.recordCount = pud.userData->GetTotalFileCount();
            pud.stats.recordSize = pud.userData->GetTotalStorageBytes();
        }

        SLOGI("Storage stats for user %{public}d: total=%{public}zu/%{public}lldB, "
            "local=%{public}zu/%{public}lldB, cast=%{public}zu/%{public}lldB, history=%{public}zu/%{public}lldB",
            userId, pud.stats.totalCount, static_cast<long long>(pud.stats.totalSize),
            pud.stats.localCount, static_cast<long long>(pud.stats.localSize),
            pud.stats.castCount, static_cast<long long>(pud.stats.castSize),
            pud.stats.historyCount, static_cast<long long>(pud.stats.historySize));

        // Emit SUMMARY entry immediately.
        std::string summary = "SUMMARY";
        summary += "|USER_ID=" + std::to_string(userId);
        summary += "|TOTAL_COUNT=" + std::to_string(pud.stats.totalCount);
        summary += "|TOTAL_SIZE=" + std::to_string(pud.stats.totalSize);
        summary += "|LOCAL_COUNT=" + std::to_string(pud.stats.localCount);
        summary += "|LOCAL_SIZE=" + std::to_string(pud.stats.localSize);
        summary += "|CAST_COUNT=" + std::to_string(pud.stats.castCount);
        summary += "|CAST_SIZE=" + std::to_string(pud.stats.castSize);
        summary += "|HISTORY_COUNT=" + std::to_string(pud.stats.historyCount);
        summary += "|HISTORY_SIZE=" + std::to_string(pud.stats.historySize);
        summary += "|RECORD_COUNT=" + std::to_string(pud.stats.recordCount);
        summary += "|RECORD_SIZE=" + std::to_string(pud.stats.recordSize);
        bundleNames.push_back(summary);

        perUser.push_back(std::move(pud));
    }

    // Second pass: fill FILE detail entries into remaining slots.
    for (const auto& pud : perUser) {
        if (bundleNames.size() >= MAX_BUNDLE_NAMES) {
            break;
        }
        if (pud.userData != nullptr) {
            pud.userData->AppendFileInfoStrings(bundleNames, MAX_BUNDLE_NAMES);
        }
    }

    // Even when there is no data at all (empty disk, empty map), the periodic timer must
    // still emit a heartbeat event so the receiver knows the service is alive.
    if (bundleNames.empty()) {
        bundleNames.push_back("SUMMARY|USER_ID=-1|TOTAL_COUNT=0|TOTAL_SIZE=0|LOCAL_COUNT=0|LOCAL_SIZE=0"
            "|CAST_COUNT=0|CAST_SIZE=0|HISTORY_COUNT=0|HISTORY_SIZE=0|RECORD_COUNT=0|RECORD_SIZE=0");
    }

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
        "AVSESSION_CONTROL_BUNDLE_NAME", bundleNames,
        "AVSESSION_CONTROL_TIMESTAMP", emptyU64,
        "APP_TYPE", "storage_stats",
        "SUPPORT_INTENT", "",
        "SUPPORT_AVQUEUE", false);

    // Clear all in-memory maps after reporting.
    for (auto& pair : storageUserDataMap_) {
        pair.second->ClearFileInfo();
    }
}

void AVSessionStorageEvent::TriggerImmediateReport()
{
    // Called when a single user hits the 99-record threshold. Report all users in one
    // event (same path as the periodic timer), then clear all maps.
    ReportStorageStatistics();
}

#endif
} // namespace OHOS::AVSession
