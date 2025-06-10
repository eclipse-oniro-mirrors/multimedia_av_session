/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "avsession_sysevent.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
static const int32_t REPORT_SIZE = 100;

AVSessionSysEvent& AVSessionSysEvent::GetInstance()
{
    static AVSessionSysEvent avSessionSysEvent;
    return avSessionSysEvent;
}

AVSessionSysEvent::AVSessionSysEvent() : optCounts_ {},
    timer_(nullptr), timerId_(0), lifeCycleInfos_ {}, controllerCommandInfos_ {}, lowQualityInfos_ {}
{
}

void AVSessionSysEvent::AddOperationCount(Operation operation)
{
    std::lock_guard lockGuard(lock_);
    auto it = optCounts_.find(operation);
    if (it == optCounts_.end()) {
        optCounts_.insert(std::make_pair(operation, 0));
        it = optCounts_.find(operation);
    }
    it->second++;
}

void AVSessionSysEvent::Reset()
{
    std::lock_guard lockGuard(lock_);
    optCounts_.clear();
    lifeCycleInfos_.clear();
    controllerCommandInfos_.clear();
    audioStatuses_.clear();
    lowQualityInfos_.clear();
}

void AVSessionSysEvent::ReportLowQuality()
{
    std::lock_guard lockGuard(lock_);
    for (auto it = lowQualityInfos_.begin(); it != lowQualityInfos_.end(); it++) {
        SLOGD("report low quality for %{public}s", it->second.bundleName_.c_str());
        HiSysWriteStatistic("PLAYING_COMBIND_AVSESSION_STATIS",
            "BUNDLE_NAME", it->second.bundleName_,
            "PLAY_DURATION", it->second.playDuration_,
            "STREAM_USAGE", it->second.streamUsage_,
            "PLAY_BACK", it->second.isBack_,
            "AUDIO_ACTIVE", it->second.isAudioActive_,
            "AVSESSION_META_QUALITY", it->second.metaDataQuality_,
            "AVSESSION_COMMAND_QUALITY", it->second.cmdQuality_,
            "AVSESSION_PLAYBACK_STATE", it->second.playbackState_);
    }
}

void AVSessionSysEvent::Regiter()
{
    if (timer_ != nullptr) {
        return;
    }

    timer_ = std::make_unique<OHOS::Utils::Timer>("EventStatisticTimer");
    auto timeCallback = [this]() {
        std::lock_guard lockGuard(lock_);
        HiSysWriteStatistic("CONTROL_COMMAND_STATISTICS", "PLAY_COUNT", optCounts_[Operation::OPT_PLAY],
            "PAUSE_COUNT", optCounts_[Operation::OPT_PAUSE], "STOP_COUNT", optCounts_[Operation::OPT_STOP],
            "PLAY_NEXT_COUNT", optCounts_[Operation::OPT_PLAY_NEXT],
            "PLAY_PREVIOUS_COUNT", optCounts_[Operation::OPT_PLAY_PREVIOUS],
            "FAST_FORWARD_COUNT", optCounts_[Operation::OPT_FAST_FORWARD],
            "REWIND_COUNT", optCounts_[Operation::OPT_REWIND],
            "SEEK_COUNT", optCounts_[Operation::OPT_SEEK],
            "SET_SPEED_COUNT", optCounts_[Operation::OPT_SET_SPEED],
            "SET_LOOP_MODE_COUNT", optCounts_[Operation::OPT_SET_LOOP_MODE],
            "SET_TARGET_LOOP_MODE_COUNT", optCounts_[Operation::OPT_SET_TARGET_LOOP_MODE],
            "TOGGLE_FAVORITE_COUNT", optCounts_[Operation::OPT_TOGGLE_FAVORITE]);

        for (const auto& it : lifeCycleInfos_) {
            HiSysWriteStatistic("SESSION_LIFECYCLE_STATISTICS", "BUNDLE_NAME", it.bundleName_,
                "APP_STATUS", it.appStatus_, "SESSION_TYPE", it.sessionType_,
                "SESSION_LIFE_CYCLE", it.isCreateSession_);
        }

        for (const auto& it : controllerCommandInfos_) {
            HiSysWriteStatistic("CONTROL_COMMAND_STATISTICS", "BUNDLE_NAME", it.bundleName_,
                "CONTROLLER_PID", it.controllerPid_, "CMD", it.controllerCmd_,
                "DETAILED_MSG", "receiver handle command");
        }

        ReportLowQuality();

        HiSysWriteStatistic("SESSION_LIFECYCLE_STATISTICS",
            "CREATE_SESSION_COUNT", optCounts_[Operation::OPT_CREATE_SESSION],
            "DELETE_SESSION_COUNT", optCounts_[Operation::OPT_DELETE_SESSION]);

        uint32_t allCtrlCmdCount = optCounts_[Operation::OPT_ALL_CTRL_COMMAND];
        uint32_t allSuccCmdCount = optCounts_[Operation::OPT_SUCCESS_CTRL_COMMAND];
        if ((allCtrlCmdCount != 0) && (allSuccCmdCount <= allCtrlCmdCount)) {
            // LCOV_EXCL_START
            float failedRate = (allCtrlCmdCount - allSuccCmdCount) / (allCtrlCmdCount * MULTIPLE);
            HiSysWriteStatistic("CONTROL_COMMAND_FAILED_RATE", "ALL_CTRL_COMMAND_COUNT", allCtrlCmdCount,
                "ALL_SUCCESS_CTRL_COMMAND", allSuccCmdCount, "COMMAND_FAILED_RATE", failedRate);
        } else {
            HiSysWriteStatistic("CONTROL_COMMAND_FAILED_RATE", "ALL_CTRL_COMMAND_COUNT", allCtrlCmdCount,
                "ALL_SUCCESS_CTRL_COMMAND", allSuccCmdCount, "COMMAND_FAILED_RATE", 0);
            // LCOV_EXCL_STOP
        }
        Reset();
    };
    timerId_ = timer_->Register(timeCallback, NOTIFY_TIME_INTERVAL, false);
    timer_->Setup();
}

// LCOV_EXCL_START
void AVSessionSysEvent::Unregister()
{
    if (timer_ != nullptr) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
}
// LCOV_EXCL_STOP

void AVSessionSysEvent::AddLifeCycleInfo(const std::string& bundleName, bool appStatus,
    const int32_t& sessionType, bool isCreateSession)
{
    AVSessionSysEvent::LifeCycleInfo lifeCycleInfo;
    lifeCycleInfo.bundleName_ = bundleName;
    lifeCycleInfo.appStatus_ = appStatus;
    lifeCycleInfo.sessionType_ = sessionType;
    lifeCycleInfo.isCreateSession_ = isCreateSession;
    lifeCycleInfos_.push_back(lifeCycleInfo);
}

void AVSessionSysEvent::AddLowQualityInfo(AVSessionSysEvent::BackControlReportInfo &reportInfo)
{
    if (lowQualityInfos_.find(reportInfo.bundleName_) == lowQualityInfos_.end()) {
        lowQualityInfos_.insert(std::make_pair(reportInfo.bundleName_, reportInfo));
    }
}

// LCOV_EXCL_START
void AVSessionSysEvent::AddControllerCommandInfo(const std::string& bundleName, const pid_t& controllerPid,
    const int32_t& controllerCmd, const int32_t& sessionType)
{
    AVSessionSysEvent::ControllerCommandInfo controllerCommandInfo;
    controllerCommandInfo.bundleName_ = bundleName;
    controllerCommandInfo.controllerPid_ = controllerPid;
    controllerCommandInfo.controllerCmd_ = controllerCmd;
    controllerCommandInfos_.push_back(controllerCommandInfo);
}

int32_t AVSessionSysEvent::GetAudioStatus(pid_t uid)
{
    std::lock_guard lockGuard(lock_);
    if (audioStatuses_.find(uid) != audioStatuses_.end()) {
        return audioStatuses_[uid];
    }
    return 0;
}
// LCOV_EXCL_STOP

void AVSessionSysEvent::SetAudioStatus(pid_t uid, int32_t rendererState)
{
    std::lock_guard lockGuard(lock_);
    audioStatuses_[uid] = rendererState;
}

void AVSessionSysEvent::ReportPlayingState(const std::string& bundleName)
{
    std::lock_guard lockGuard(lock_);
    if (playingStateInfos_.empty()) {
        return;
    }

    if (playingStateInfos_.find(bundleName) == playingStateInfos_.end()) {
        return;
    }

    auto playingStateInfo = playingStateInfos_[bundleName].get();
    if (playingStateInfo != nullptr) {
        SLOGD("report playing state for %{public}s", playingStateInfo->bundleName_.c_str());
        HiSysWriteStatistic("PLAYING_AVSESSION_STATS",
            "APP_NAME", playingStateInfo->bundleName_,
            "APP_VERSION", playingStateInfo->appVersion_,
            "AVSESSION_STATE", playingStateInfo->state_,
            "AVSESSION_STATE_TIMESTAMP", playingStateInfo->stateTime_,
            "AVSESSION_META_QUALITY", playingStateInfo->metaQuality_,
            "AVSESSION_META_QUALITY_TIMESTAMP", playingStateInfo->metaQualityTime_,
            "AVSESSION_COMMAND_QUALITY", playingStateInfo->commandQuality_,
            "AVSESSION_COMMAND_QUA_TIMESTAMP", playingStateInfo->commandQualityTime_,
            "AVSESSION_PLAYSTATE", playingStateInfo->playbackState_,
            "AVSESSION_PLAYSTATE_TIMESTAMP", playingStateInfo->playbackStateTime_,
            "AVSESSION_CONTROL", playingStateInfo->control_,
            "AVSESSION_CONTROL_BUNDLE_NAME", playingStateInfo->callerBundleName_,
            "AVSESSION_CONTROL_TIMESTAMP", playingStateInfo->controlTime_);
    }
    playingStateInfos_.erase(bundleName);
}

void AVSessionSysEvent::ReportPlayingStateAll()
{
    std::lock_guard lockGuard(lock_);
    std::vector<std::string> keys;
    for (const auto& it : playingStateInfos_) {
        keys.push_back(it.first);
    }
    for (const auto& key : keys) {
        ReportPlayingState(key);
    }
}

void AVSessionSysEvent::RegisterPlayingState()
{
    if (playingStateTimer_ != nullptr) {
        return;
    }

    playingStateTimer_ = std::make_unique<OHOS::Utils::Timer>("PlayingStatisticTimer");
    auto timeCallback = [this]() {
        ReportPlayingStateAll();
    };
    playingStateTimerId_ = playingStateTimer_->Register(timeCallback, PLAYING_STATE_CHECK_INTERVAL, false);
    playingStateTimer_->Setup();
}

void AVSessionSysEvent::UnRegisterPlayingState()
{
    if (playingStateTimer_ != nullptr) {
        playingStateTimer_->Shutdown();
        playingStateTimer_->Unregister(playingStateTimerId_);
        playingStateTimer_ = nullptr;
    }
}

static int64_t UTCTimeMilliSeconds()
{
    struct timespec t;
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_MSEC + t.tv_nsec / MSEC_TO_NSEC;
}

PlayingStateInfo* AVSessionSysEvent::GetPlayingStateInfo(const std::string& bundleName)
{
    std::lock_guard lockGuard(lock_);
    if (playingStateInfos_.find(bundleName) == playingStateInfos_.end()) {
        playingStateInfos_.insert({bundleName, std::make_unique<PlayingStateInfo>()});
        playingStateInfos_[bundleName]->bundleName_ = bundleName;
    }
    return playingStateInfos_[bundleName].get();
}

void AVSessionSysEvent::UpdateState(const std::string& bundleName, const std::string& appVersion, uint8_t state)
{
    std::lock_guard lockGuard(lock_);
    PlayingStateInfo* playingStateInfo = GetPlayingStateInfo(bundleName);
    if (playingStateInfo == nullptr) {
        return;
    }
    playingStateInfo->bundleName_ = bundleName;
    playingStateInfo->appVersion_ = appVersion;
    playingStateInfo->updateState(state);
}

void AVSessionSysEvent::UpdateMetaQuality(const std::string& bundleName, MetadataQuality metaQuality)
{
    std::lock_guard lockGuard(lock_);
    PlayingStateInfo* playingStateInfo = GetPlayingStateInfo(bundleName);
    if (playingStateInfo == nullptr) {
        return;
    }
    playingStateInfo->updateMetaQuality(metaQuality);
}

void AVSessionSysEvent::UpdateCommandQuality(const std::string& bundleName, uint32_t commandQuality)
{
    std::lock_guard lockGuard(lock_);
    PlayingStateInfo* playingStateInfo = GetPlayingStateInfo(bundleName);
    if (playingStateInfo == nullptr) {
        return;
    }
    playingStateInfo->updateCommandQuality(commandQuality);
}

void AVSessionSysEvent::UpdatePlaybackState(const std::string& bundleName, uint8_t playbackState)
{
    std::lock_guard lockGuard(lock_);
    PlayingStateInfo* playingStateInfo = GetPlayingStateInfo(bundleName);
    if (playingStateInfo == nullptr) {
        return;
    }
    playingStateInfo->updatePlaybackState(playbackState);
}

void AVSessionSysEvent::UpdateControl(const std::string& bundleName, uint8_t control, std::string callerBundleName)
{
    std::lock_guard lockGuard(lock_);
    PlayingStateInfo* playingStateInfo = GetPlayingStateInfo(bundleName);
    if (playingStateInfo == nullptr) {
        return;
    }
    playingStateInfo->updateControl(control, callerBundleName);
}

void PlayingStateInfo::updateState(uint8_t state)
{
    std::lock_guard lockGuard(lock_);
    if (state != lastState_) {
        lastState_ = state;
        state_.push_back(state);
        stateTime_.push_back(UTCTimeMilliSeconds());
        if (state_.size() >= REPORT_SIZE) {
            AVSessionSysEvent::GetInstance().ReportPlayingState(bundleName_);
        }
    }
}

void PlayingStateInfo::updateMetaQuality(MetadataQuality metaQuality)
{
    std::lock_guard lockGuard(lock_);
    metaQuality_.push_back(static_cast<uint8_t>(metaQuality));
    metaQualityTime_.push_back(UTCTimeMilliSeconds());
    if (metaQuality_.size() >= REPORT_SIZE) {
        AVSessionSysEvent::GetInstance().ReportPlayingState(bundleName_);
    }
}

void PlayingStateInfo::updateCommandQuality(uint32_t commandQuality)
{
    std::lock_guard lockGuard(lock_);
    if (commandQuality != lastCommandQuality_) {
        lastCommandQuality_ = commandQuality;
        commandQuality_.push_back(commandQuality);
        commandQualityTime_.push_back(UTCTimeMilliSeconds());
        if (commandQuality_.size() >= REPORT_SIZE) {
            AVSessionSysEvent::GetInstance().ReportPlayingState(bundleName_);
        }
    }
}

void PlayingStateInfo::updatePlaybackState(uint8_t playbackState)
{
    std::lock_guard lockGuard(lock_);
    if (playbackState != lastPlaybackState_) {
        lastPlaybackState_ = playbackState;
        playbackState_.push_back(playbackState);
        playbackStateTime_.push_back(UTCTimeMilliSeconds());
        if (playbackState_.size() >= REPORT_SIZE) {
            AVSessionSysEvent::GetInstance().ReportPlayingState(bundleName_);
        }
    }
}

void PlayingStateInfo::updateControl(uint8_t control, std::string callerBundleName)
{
    std::lock_guard lockGuard(lock_);
    if (control != lastControl_) {
        lastControl_ = control;
        control_.push_back(control);
        callerBundleName_.push_back(callerBundleName);
        controlTime_.push_back(UTCTimeMilliSeconds());
        if (control_.size() >= REPORT_SIZE) {
            AVSessionSysEvent::GetInstance().ReportPlayingState(bundleName_);
        }
    }
}
#endif
} // namespace OHOS::AVSession