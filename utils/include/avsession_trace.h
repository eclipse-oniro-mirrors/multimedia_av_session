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
#include "hitrace_meter.h"

namespace OHOS::AVSession {
enum AVSessionTraceTaskId : int32_t {
    INVALID_TASK_ID = -1,
    NAPI_SET_AV_META_DATA_TASK_ID,
    NAPI_SET_AV_PLAYBACK_STATE_TASK_ID,
    NAPI_SET_LAUNCH_ABILITY_TASK_ID,
    NAPI_GET_CONTROLLER_TASK_ID,
    NAPI_ACTIVATE_TASK_ID,
    NAPI_DEACTIVATE_TASK_ID,
    NAPI_AVSESSION_DESTROY_TASK_ID,
    NAPI_AVSESSION_GET_OUTPUT_DEVICE_TASK_ID,
    NAPI_GET_AV_PLAYBACK_STATE_TASK_ID,
    NAPI_GET_AV_META_DATA_TASK_ID,
    NAPI_SEND_AV_KEY_EVENT_TASK_ID,
    NAPI_GET_LAUNCH_ABILITY_TASK_ID,
    NAPI_IS_ACTIVE_TASK_ID,
    NAPI_AVSESSION_CONTROLLER_DESTROY_TASK_ID,
    NAPI_GET_VALID_COMMANDS_TASK_ID,
    NAPI_SEND_CONTROL_COMMAND_TASK_ID,
    NAPI_CREATE_AVSESSION_TASK_ID,
    NAPI_GET_ALL_SESSION_DESCRIPTORS_TASK_ID,
    NAPI_CREATE_CONTROLLER_TASK_ID,
    NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID,
    NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID,
    NAPI_SET_AUDIO_STREAM_ID_TASK_ID
};

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
    AVSessionTrace& operator= (const AVSessionTrace&) = delete;

    AVSessionTrace(AVSessionTrace&&) = delete;
    AVSessionTrace& operator= (AVSessionTrace&&) = delete;
private:
    bool isSync_ = false;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_TRACE_H