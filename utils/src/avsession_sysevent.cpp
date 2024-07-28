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

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
AVSessionSysEvent& AVSessionSysEvent::GetInstance()
{
    static AVSessionSysEvent avSessionSysEvent;
    return avSessionSysEvent;
}

AVSessionSysEvent::AVSessionSysEvent() : optCounts_ {},
    timer_(nullptr), timerId_(0), lifeCycleInfos_ {}, controllerCommandInfos_ {}
{
}

void AVSessionSysEvent::AddOperationCount(Operation operation)
{
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
}

void AVSessionSysEvent::Regiter()
{
    if (timer_ != nullptr) {
        return;
    }

    timer_ = std::make_unique<OHOS::Utils::Timer>("EventStatisticTimer");
    auto timeCallback = [this]() {
        HiSysWriteStatistic("CONTROL_COMMAND_STATISTICS", "PLAY_COUNT", optCounts_[Operation::OPT_PLAY],
            "PAUSE_COUNT", optCounts_[Operation::OPT_PAUSE], "STOP_COUNT", optCounts_[Operation::OPT_STOP],
            "PLAY_NEXT_COUNT", optCounts_[Operation::OPT_PLAY_NEXT],
            "PLAY_PREVIOUS_COUNT", optCounts_[Operation::OPT_PLAY_PREVIOUS],
            "FAST_FORWARD_COUNT", optCounts_[Operation::OPT_FAST_FORWARD],
            "REWIND_COUNT", optCounts_[Operation::OPT_REWIND],
            "SEEK_COUNT", optCounts_[Operation::OPT_SEEK],
            "SET_SPEED_COUNT", optCounts_[Operation::OPT_SET_SPEED],
            "SET_LOOP_MODE_COUNT", optCounts_[Operation::OPT_SET_LOOP_MODE],
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

#endif
} // namespace OHOS::AVSession