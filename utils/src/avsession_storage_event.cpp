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

static int64_t GetFileSizeBytes(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<int64_t>(st.st_size);
}

static int64_t GetCurrentTimestampMs()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

static std::string FormatTimestamp(int64_t ms)
{
    const int64_t MS_PER_SEC = 1000;
    time_t sec = static_cast<time_t>(ms / MS_PER_SEC);
    int64_t millis = ms % MS_PER_SEC;
    struct tm tmResult {};
    if (localtime_r(&sec, &tmResult) == nullptr) {
        return std::to_string(ms);
    }
    char buf[40] = {0};
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmResult) == 0) {
        return std::to_string(ms);
    }
    return std::string(buf) + "." + std::to_string(MS_PER_SEC + millis).substr(1);
}

static std::string AnonymizeFilePath(const std::string& path)
{
    static constexpr const char* EL2_PREFIX = "/data/service/el2/";
    std::string shortPath = (path.find(EL2_PREFIX) == 0) ? path.substr(strlen(EL2_PREFIX)) : path;
    size_t slash = shortPath.find_last_of('/');
    if (slash == std::string::npos) {
        return shortPath;
    }
    std::string dir = shortPath.substr(0, slash + 1);
    std::string fileName = shortPath.substr(slash + 1);
    std::string suffix = AVSessionUtils::GetFileSuffix();
    size_t suffixPos = fileName.rfind(suffix);
    std::string stem = (suffixPos != std::string::npos && suffixPos > 0)
        ? fileName.substr(0, suffixPos) : fileName;
    std::string anonyStem = (stem.find("cast_") == 0)
        ? "cast_" + AVSessionUtils::GetAnonySessionId(stem.substr(5))
        : (stem.find('_') != std::string::npos)
            ? stem
            : AVSessionUtils::GetAnonySessionId(stem);
    return dir + anonyStem + suffix;
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
    timer_ = std::make_unique<Utils::Timer>("StorageEventTimer");
    Utils::Timer::TimerCallback timerCallback = [this]() {
        ReportStorageStatistics();
    };
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
    info.fileSize_ = GetFileSizeBytes(fileName);
    info.timestamp_ = GetCurrentTimestampMs();
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

int64_t StorageUserData::GetTotalStorageBytes()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    int64_t total = 0;
    for (const auto& pair : fileInfoMap_) {
        total += pair.second.fileSize_;
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
        item += "|NAME=" + AnonymizeFilePath(pair.first);
        item += "|SIZE=" + std::to_string(info.fileSize_);
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
    StorageUserData& userData = GetOrCreateStorageUserData(userId);
    userData.AddFileInfo(fileName, bundleName);

    size_t totalFileRecords = 0;
    for (const auto& pair : storageUserDataMap_) {
        totalFileRecords += pair.second->GetTotalFileCount();
    }
    if (storageUserDataMap_.size() + totalFileRecords >= MAX_BUNDLE_NAMES) {
        SLOGI("Bundle size reaches limit, trigger immediate report");
        TriggerImmediateReport();
    }
}

void AVSessionStorageEvent::RecordFileDelete(const std::string& fileName, int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    auto it = storageUserDataMap_.find(userId);
    if (it == storageUserDataMap_.end()) {
        return;
    }
    it->second->RemoveFileInfo(fileName);
}

void AVSessionStorageEvent::RecordSessionInfo(const std::string& sessionId,
    const std::string& bundleName, int32_t userId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    sessionInfoMap_[userId][sessionId] = bundleName;
}

void AVSessionStorageEvent::RemoveSessionInfo(const std::string& sessionId)
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    for (auto& pair : sessionInfoMap_) {
        pair.second.erase(sessionId);
    }
}

void AVSessionStorageEvent::ScanStorageStatistics(int32_t userId, StorageStatistics& stats)
{
    stats = StorageStatistics{};
    const std::string suffix = AVSessionUtils::GetFileSuffix();
    const std::string castPrefix = "cast_";

    std::set<std::string> allFiles;
    std::vector<std::string> dirFiles;
    OHOS::GetDirFiles(AVSessionUtils::GetCachePathName(userId), dirFiles);
    OHOS::GetDirFiles(AVSessionUtils::GetFixedPathName(userId), dirFiles);
    auto it = storageUserDataMap_.find(userId);
    if (it != storageUserDataMap_.end()) {
        for (const auto& pair : it->second->GetFileInfoMapForScan()) {
            allFiles.insert(pair.first);
        }
    }
    for (const auto& f : dirFiles) { allFiles.insert(f); }

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
    static constexpr const char* EL2_ROOT = "/data/service/el2/";
    static constexpr const char* PUBLIC_DIR = "public";
    DIR* dir = opendir(EL2_ROOT);
    if (dir == nullptr) {
        SLOGW("EnumerateUserIds: opendir failed for %{public}s", EL2_ROOT);
        return userIds;
    }
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name == "." || name == ".." || name == PUBLIC_DIR) {
            continue;
        }
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) {
            continue;
        }
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st {};
            std::string full = std::string(EL2_ROOT) + name;
            if (stat(full.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                continue;
            }
        }
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

std::set<int32_t> AVSessionStorageEvent::CollectAllUsers()
{
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);
    std::vector<int32_t> diskUsers = EnumerateUserIds();
    std::set<int32_t> allUsers(diskUsers.begin(), diskUsers.end());
    for (const auto& pair : storageUserDataMap_) {
        allUsers.insert(pair.first);
    }
    return allUsers;
}

std::string AVSessionStorageEvent::BuildSummary(int32_t userId, const StorageStatistics& stats)
{
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
    summary += "|SESSIONS=";
    auto sessionIt = sessionInfoMap_.find(userId);
    if (sessionIt != sessionInfoMap_.end()) {
        bool first = true;
        for (const auto& sp : sessionIt->second) {
            if (!first) { summary += ";"; }
            summary += AVSessionUtils::GetAnonySessionId(sp.first) + "," + sp.second;
            first = false;
        }
    }
    return summary;
}

void AVSessionStorageEvent::EmitStorageEvent(const std::vector<std::string>& bundleNames)
{
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
        "SUPPORT_INTENT", "0",
        "SUPPORT_AVQUEUE", false);
}

void AVSessionStorageEvent::ReportStorageStatistics()
{
    SLOGI("ReportStorageStatistics for all users");
    std::lock_guard<std::recursive_mutex> lockGuard(lock_);

    std::set<int32_t> allUsers = CollectAllUsers();
    std::vector<std::string> bundleNames;
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
        bundleNames.push_back(BuildSummary(userId, pud.stats));
        perUser.push_back(std::move(pud));
    }

    for (const auto& pud : perUser) {
        if (bundleNames.size() >= MAX_BUNDLE_NAMES) {
            break;
        }
        if (pud.userData != nullptr) {
            pud.userData->AppendFileInfoStrings(bundleNames, MAX_BUNDLE_NAMES);
        }
    }

    if (bundleNames.empty()) {
        bundleNames.push_back(BuildSummary(-1, StorageStatistics{}));
    }

    EmitStorageEvent(bundleNames);

    for (auto& pair : storageUserDataMap_) {
        pair.second->ClearFileInfo();
    }
}

void AVSessionStorageEvent::TriggerImmediateReport()
{
    ReportStorageStatistics();
}

#endif
} // namespace OHOS::AVSession
