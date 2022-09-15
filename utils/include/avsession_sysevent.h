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

#ifndef OHOS_AVSESSION_SYSEVENT_H
#define OHOS_AVSESSION_SYSEVENT_H

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#include <mutex>
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
class AVSessionSysEvent {
public:
    struct LifeCycleInfo {
        std::string bundleName_;
        bool appStatus_;
        int32_t sessionType_;
        bool isCreateSession_;
    };

    struct ControllerCommandInfo {
        std::string bundleName_;
        pid_t controllerPid_;
        int32_t controllerCmd_;
    };

    static AVSessionSysEvent& GetInstance();

    template<typename... Types>
    static int HiSysWriteFault(const std::string& eventName, Types... keyValues)
    {
        return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteStatistic(const std::string& eventName, Types... keyValues)
    {
        return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteSecurity(const std::string& eventName, Types... keyValues)
    {
        return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
            OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY, keyValues...);
    }

    template<typename... Types>
    static int HiSysWriteBehavior(const std::string& eventName, Types... keyValues)
    {
        return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::AV_SESSION, eventName,
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
    void SetAudioStatus(int32_t uid, int32_t rendererState);
    int32_t GetAudioStatus(int32_t uid);

private:
    std::map<int32_t, int32_t> audioStatuses_;
    AVSessionSysEvent();
    std::map<Operation, uint32_t> optCounts_;
    std::unique_ptr<Utils::Timer> timer_;
    uint32_t timerId_;
    std::recursive_mutex lock_;
    static constexpr uint32_t NOTIFY_TIME_INTERVAL = 12 * 60 * 60 * 1000; // retry after 12 hours
    std::list<AVSessionSysEvent::LifeCycleInfo> lifeCycleInfos_;
    std::list<AVSessionSysEvent::ControllerCommandInfo> controllerCommandInfos_;
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
    } while (0)                                                                                                 \

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