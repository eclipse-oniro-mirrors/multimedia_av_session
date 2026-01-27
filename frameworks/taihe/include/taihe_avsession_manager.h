/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef TAIHE_AV_SESSION_MANAGER_H
#define TAIHE_AV_SESSION_MANAGER_H

#include <map>
#include <list>
#include "avsession_manager.h"
#include "avsession_trace.h"
#include "taihe_avsession_enum.h"
#include "taihe_utils.h"
#include "taihe_session_listener.h"
#include "event_handler.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVSessionManager {
public:
    static constexpr int32_t HISTORICAL_UNSET_NUM = 3;
    static constexpr int32_t HISTORICAL_MIN_NUM = 0;
    static constexpr int32_t HISTORICAL_MAX_NUM = 10;

    using OnEventHandlerType = std::function<int32_t(std::shared_ptr<uintptr_t> &callback)>;
    using OffEventHandlerType = std::function<int32_t(std::shared_ptr<uintptr_t> &callback)>;
    static std::map<int32_t, int32_t> errcode_;

    static void HandleServiceDied();
    static void HandleServiceStart();

    static void ReportStartCastDiscoveryFailInfo(std::string func, int32_t error);
    static void ReportStopCastDiscoveryFailInfo(std::string func, int32_t error);
    static void ReportStartCastFailInfo(int32_t error);
    static void ReportStartCastFailInfo(int32_t error, const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfo);
    static void ReportStopCastFailInfo(int32_t error);

    static int32_t OnEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback);
    static int32_t OffEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback);
    static int32_t OnDistributedSessionChangeEvent(OHOS::AVSession::DistributedSessionType sessionType,
        std::shared_ptr<uintptr_t> &callback);
    static int32_t OffDistributedSessionChangeEvent(OHOS::AVSession::DistributedSessionType sessionType,
        std::shared_ptr<uintptr_t> &callback);
    static int32_t OnActiveSessionChangedEvent(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffActiveSessionChangedEvent(std::shared_ptr<uintptr_t> &callback);

    static int32_t OnSessionCreate(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnSessionDestroy(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnTopSessionChange(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnAudioSessionChecked(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnDeviceAvailable(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnDeviceLogEvent(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnDeviceOffline(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnDeviceStateChanged(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnServiceDie(std::shared_ptr<uintptr_t> &callback);
    static int32_t OnRemoteDistributedSessionChange(std::shared_ptr<uintptr_t> &callback);

    static int32_t OffSessionCreate(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffSessionDestroy(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffTopSessionChange(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffAudioSessionChecked(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffDeviceAvailable(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffDeviceLogEvent(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffDeviceOffline(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffDeviceStateChanged(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffServiceDie(std::shared_ptr<uintptr_t> &callback);
    static int32_t OffRemoteDistributedSessionChange(std::shared_ptr<uintptr_t> &callback);

private:
    static int32_t RegisterNativeSessionListener();
    static void ExecuteCallback(std::shared_ptr<uintptr_t> method);

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;
    static std::shared_ptr<TaiheSessionListener> listener_;
    static std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    static std::list<std::shared_ptr<uintptr_t>> serviceDiedCallbacks_;
    static std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
    static std::map<OHOS::AVSession::DistributedSessionType, std::pair<OnEventHandlerType, OffEventHandlerType>>
        distributedControllerEventHandlers_;
    static const std::string DISTRIBUTED_SESSION_CHANGE_EVENT;
};
} // namespace ANI::AVSession
#endif // TAIHE_AV_SESSION_MANAGER_H