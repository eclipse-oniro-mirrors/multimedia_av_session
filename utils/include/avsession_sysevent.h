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

#ifndef OHOS_AVSESSION_SYSEVENT_H
#define OHOS_AVSESSION_SYSEVENT_H

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#include <mutex>
#include "avcontrol_command.h"
#include "hisysevent.h"
#include "timer.h"
#endif

namespace OHOS::AVSession {
enum class Operation {
    OPT_PLAY = 0,
    OPT_PAUSE,
    OPT_STOP,
    OPT_PLAY_NEXT,
    OPT_PLAY_PREVIOUS,
    OPT_FAST_FORWARD,
    OPT_REWIND,
    OPT_SEEK,
    OPT_SET_SPEED,
    OPT_SET_LOOP_MODE,
    OPT_SET_TARGET_LOOP_MODE,
    OPT_TOGGLE_FAVORITE,
    OPT_MEDIA_KEY_EVENT,
    OPT_OUTPUT_DEVICE_CHANGED,
    OPT_COMMAND_MAX,
    OPT_CREATE_SESSION,
    OPT_DELETE_SESSION,
    OPT_ALL_CTRL_COMMAND,
    OPT_SUCCESS_CTRL_COMMAND,
};

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
enum MetadataQuality {
    METADATA_QUALITY_NONE = 0,
    METADATA_QUALITY_TITLE,
    METADATA_QUALITY_IMG,
    METADATA_QUALITY_BOTH,
};

enum class SessionState {
    STATE_CREATE = 0,
    STATE_RELEASE,
    STATE_INITIAL,
};

class PlayingStateInfo {
public:
    void updateState(SessionState state);
    void updateMetaQuality(MetadataQuality metaQuality);
    void updateCommandQuality(uint32_t commandQuality);
    void updatePlaybackState(uint8_t playbackState);
    void updateControl(uint8_t control, std::string callerBundleName);

    std::string bundleName_ = "";
    std::string appVersion_ = "";
    std::vector<uint8_t> state_;
    std::vector<uint64_t> stateTime_;
    std::vector<uint8_t> metaQuality_;
    std::vector<uint64_t> metaQualityTime_;
    std::vector<uint32_t> commandQuality_;
    std::vector<uint64_t> commandQualityTime_;
    std::vector<uint8_t> playbackState_;
    std::vector<uint64_t> playbackStateTime_;
    std::vector<uint8_t> control_;
    std::vector<std::string> callerBundleName_;
    std::vector<uint64_t> controlTime_;
private:
    SessionState lastState_ = SessionState::STATE_INITIAL;
    uint32_t lastCommandQuality_ = 0;
    uint8_t lastPlaybackState_ = 0;
    uint8_t lastControl_ = AVControlCommand::SESSION_CMD_MAX;
    std::recursive_mutex lock_;
};

class AVSessionSysEvent {
public:
    struct LifeCycleInfo {
        std::string bundleName_ = "";
        bool appStatus_ = false;
        int32_t sessionType_ = 0;
        bool isCreateSession_ = false;
    };

    struct ControllerCommandInfo {
        std::string bundleName_ = "";
        pid_t controllerPid_ = 0;
        int32_t controllerCmd_ = 0;
    };

    struct BackControlReportInfo {
        std::string bundleName_ = "";
        int32_t streamUsage_ = 0;
        bool isBack_ = false;
        int32_t playDuration_ = 0;
        bool isAudioActive_ = false;
        int32_t metaDataQuality_ = 0;
        int32_t cmdQuality_ = 0;
        int32_t playbackState_ = 0;
    };

    static AVSessionSysEvent& GetInstance();

    template<typename... Types>
    static int HiSysWriteFault(const std::string& eventName, Types... keyValues)
    {
        return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteStatistic(const std::string& eventName, Types... keyValues)
    {
        return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteSecurity(const std::string& eventName, Types... keyValues)
    {
        return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteBehavior(const std::string& eventName, Types... keyValues)
    {
        return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, keyValues...);
    }

    void Reset();
    void Regiter();
    void Unregister();
    void AddOperationCount(Operation operation);
    void AddLifeCycleInfo(const std::string& bundleName, bool appStatus,
        const int32_t& sessionType, bool isCreateSession);
    void AddControllerCommandInfo(const std::string& bundleName, const pid_t& controllerPid,
        const int32_t& controllerCmd, const int32_t& sessionType);
    void AddLowQualityInfo(AVSessionSysEvent::BackControlReportInfo &reportInfo);
    void SetAudioStatus(pid_t uid, int32_t rendererState);
    int32_t GetAudioStatus(pid_t uid);
    void ReportLowQuality();

    void ReportPlayingState(const std::string& bundleName);
    void ReportPlayingStateAll();
    void UpdateState(const std::string& bundleName, const std::string& appVersion, SessionState state);
    void UpdateMetaQuality(const std::string& bundleName, MetadataQuality metaQuality);
    void UpdateCommandQuality(const std::string& bundleName, uint32_t commandQuality);
    void UpdatePlaybackState(const std::string& bundleName, uint8_t playbackState);
    void UpdateControl(const std::string& bundleName, uint8_t control, std::string callerBundleName);

private:
    PlayingStateInfo* GetPlayingStateInfo(const std::string& bundleName);
    std::map<pid_t, int32_t> audioStatuses_;
    AVSessionSysEvent();
    ~AVSessionSysEvent();
    std::map<Operation, uint32_t> optCounts_;
    std::unique_ptr<Utils::Timer> timer_;
    uint32_t timerId_ = 0;
    std::recursive_mutex lock_;
    static constexpr uint32_t NOTIFY_TIME_INTERVAL = 1 * 60 * 60 * 1000; // retry after 1 hours
    int32_t playingStateTriggerCount = 0;
    std::list<AVSessionSysEvent::LifeCycleInfo> lifeCycleInfos_;
    std::list<AVSessionSysEvent::ControllerCommandInfo> controllerCommandInfos_;
    std::map<std::string, AVSessionSysEvent::BackControlReportInfo> lowQualityInfos_;
    std::map<std::string, std::unique_ptr<PlayingStateInfo>> playingStateInfos_;
    static constexpr float MULTIPLE = 1.0f;
};
#endif

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#define HISYSEVENT_FAULT(eventName, ...) ((void)AVSessionSysEvent::HiSysWriteFault(eventName, __VA_ARGS__))
#define HISYSEVENT_STATISTIC(eventName, ...) ((void)AVSessionSysEvent::HiSysWriteStatistic(eventName, __VA_ARGS__))
#define HISYSEVENT_SECURITY(eventName, ...) ((void)AVSessionSysEvent::HiSysWriteSecurity(eventName, __VA_ARGS__))
#define HISYSEVENT_BEHAVIOR(eventName, ...) ((void)AVSessionSysEvent::HiSysWriteBehavior(eventName, __VA_ARGS__))
#define HISYSEVENT_RESET AVSessionSysEvent::GetInstance().Reset()
#define HISYSEVENT_REGITER AVSessionSysEvent::GetInstance().Regiter()
#define HISYSEVENT_UNREGISTER AVSessionSysEvent::GetInstance().Unregister()
#define HISYSEVENT_ADD_OPERATION_COUNT(operation) AVSessionSysEvent::GetInstance().AddOperationCount(operation)
#define HISYSEVENT_ADD_CONTROLLER_COMMAND_INFO(bundleName, controllerPid, controllerCmd, sessionType)           \
    do {                                                                                                        \
        AVSessionSysEvent::GetInstance().AddControllerCommandInfo(bundleName, controllerPid,                    \
                                                                  controllerCmd, sessionType);                  \
    } while (0)

#define HISYSEVENT_ADD_LIFE_CYCLE_INFO(bundleName, appStatus, sessionType, isCreateSession)                     \
    do {                                                                                                        \
        AVSessionSysEvent::GetInstance().AddLifeCycleInfo(bundleName, appStatus, sessionType, isCreateSession); \
    } while (0)
#define HISYSEVENT_GET_AUDIO_STATUS(uid) AVSessionSysEvent::GetInstance().GetAudioStatus(uid)
#define HISYSEVENT_SET_AUDIO_STATUS(uid, rendererState)                                                         \
    do {                                                                                                        \
        AVSessionSysEvent::GetInstance().SetAudioStatus(uid, rendererState);                                    \
    } while (0)

#else
#define HISYSEVENT_FAULT(...)
#define HISYSEVENT_STATISTIC(...)
#define HISYSEVENT_SECURITY(...)
#define HISYSEVENT_BEHAVIOR(...)
#define HISYSEVENT_RESET
#define HISYSEVENT_REGITER
#define HISYSEVENT_UNREGISTER
#define HISYSEVENT_ADD_OPERATION_COUNT(...)
#define HISYSEVENT_ADD_CONTROLLER_COMMAND_INFO(...)
#define HISYSEVENT_ADD_LIFE_CYCLE_INFO(...)
#define HISYSEVENT_GET_AUDIO_STATUS(...)
#define HISYSEVENT_SET_AUDIO_STATUS(...)
#endif
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SYSEVENT_H