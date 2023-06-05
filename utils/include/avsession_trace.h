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

#ifndef OHOS_AVSESSION_TRACE_H
#define OHOS_AVSESSION_TRACE_H

#include <string>

#ifdef ENBABLE_AVSESSION_TRACE_CONTROL
#include "hitrace_meter.h"
#endif

#ifdef ENBABLE_AVSESSION_TRACE_CONTROL
#define AVSESSION_TRACE_SYNC_START(traceName) AVSessionTrace trace(traceName)
#define AVSESSION_TRACE_ASYNC_START(traceName, taskId) AVSessionTrace::TraceBegin(traceName, taskId)
#define AVSESSION_TRACE_ASYNC_END(traceName, taskId) AVSessionTrace::TraceEnd(traceName, taskId)
#else
#define AVSESSION_TRACE_SYNC_START(...)
#define AVSESSION_TRACE_ASYNC_START(...)
#define AVSESSION_TRACE_ASYNC_END(...)

#endif
namespace OHOS::AVSession {
enum AVSessionTraceTaskId : int32_t {
    INVALID_TASK_ID = -1,
    NAPI_SET_AV_META_DATA_TASK_ID = 0,
    NAPI_SET_AV_PLAYBACK_STATE_TASK_ID = 1,
    NAPI_SEND_AV_KEY_EVENT_TASK_ID = 2,
    NAPI_SEND_CONTROL_COMMAND_TASK_ID = 3,
    NAPI_CREATE_AVSESSION_TASK_ID = 4,
    NAPI_CREATE_CONTROLLER_TASK_ID = 5,
    NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID = 6,
    NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID = 7,
    NAPI_CAST_AUDIO_TASK_ID = 8,
    NAPI_SET_SESSION_EVENT_TASK_ID = 9,
    NAPI_SEND_COMMON_COMMAND_TASK_ID = 10,
    NAPI_SKIP_TO_QUEUE_ITEM_TASK_ID = 11,
    NAPI_SET_AV_QUEUE_TITLE_TASK_ID = 12,
    NAPI_SET_AV_QUEUE_ITEMS_TASK_ID = 13,
    NAPI_SET_EXTRAS_TASK_ID = 14,
    NAPI_START_CAST_DISCOVERY= 15,
    NAPI_STOP_CAST_DISCOVERY = 16,
    NAPI_START_CAST = 17,
    NAPI_RELEASE_CAST = 18,
    NAPI_CREATE_CAST_CONTROLLER_TASK_ID = 19,
    NAPI_CAST_CONTROLLER_START_TASK_ID = 20,
    NAPI_CAST_CONTROLLER_SEND_CONTROL_COMMAND = 21,
};
#ifdef ENBABLE_AVSESSION_TRACE_CONTROL
class __attribute__((visibility("default"))) AVSessionTrace {
public:
    explicit AVSessionTrace(const std::string& traceName)
    {
        std::string avSessionTrace("AVSession:");
        avSessionTrace += traceName;
        StartTrace(HITRACE_TAG_ZMEDIA, avSessionTrace);
        isSync_ = true;
    }

    static void TraceBegin(const std::string& traceName, int32_t taskId)
    {
        if (taskId <= INVALID_TASK_ID) {
            return;
        }
        std::string traceBegin("AVSession:");
        traceBegin += traceName;
        StartAsyncTrace(HITRACE_TAG_ZMEDIA, traceBegin, taskId);
    }

    static void TraceEnd(const std::string& traceName, int32_t taskId)
    {
        if (taskId <= INVALID_TASK_ID) {
            return;
        }
        std::string traceEnd("AVSession:");
        traceEnd += traceName;
        FinishAsyncTrace(HITRACE_TAG_ZMEDIA, traceEnd, taskId);
    }

    ~AVSessionTrace()
    {
        if (isSync_) {
            FinishTrace(HITRACE_TAG_ZMEDIA);
        }
    }

    AVSessionTrace(const AVSessionTrace&) = delete;
    AVSessionTrace& operator = (const AVSessionTrace&) = delete;

    AVSessionTrace(AVSessionTrace&&) = delete;
    AVSessionTrace& operator = (AVSessionTrace&&) = delete;
private:
    bool isSync_ = false;
};
#endif
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_TRACE_H