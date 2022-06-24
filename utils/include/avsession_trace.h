/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
    ON_SESSION_DESTROY_TASK_ID = 0,
    ON_PLAYBACK_STATE_CHANGE_TASK_ID = 1,
    ON_MEDA_DATA_CHANGE_TASK_ID = 2,
    ON_ACTIVE_STATE_CHANGE_TASK_ID = 3,
    ON_VALID_COMMAND_CHANGE_TASK_ID = 4,
    ON_SESSIONCALLBACK_PLAYTASK_ID = 5,
    ON_SESSIONCALLBACK_PAUSETASK_ID = 6,
    ON_SESSIONCALLBACK_STOPTASK_ID = 7,
    ON_SESSIONCALLBACK_PLAYNEXTTASK_ID = 8,
    ON_SESSIONCALLBACK_PLAYPREVIOUSTASK_ID = 9,
    ON_SESSIONCALLBACK_FASTFORWARDTASK_ID = 10,
    ON_SESSIONCALLBACK_REWINDTASK_ID = 11,
    ON_SESSIONCALLBACK_SEEKTASK_ID = 12,
    ON_SESSIONCALLBACK_SETSPEEDTASK_ID = 13,
    ON_SESSIONCALLBACK_SETLOOPMODETASK_ID = 14,
    ON_SESSIONCALLBACK_TOGGLEFAVORITETASK_ID = 15,
    ON_SESSIONCALLBACK_MEDIAKEYEVENTTASK_ID = 16,
    ON_SESSIONSERVICE_CLIENTDIEDTASK_ID = 17,
    ON_SESSIONSERVICE_ADDSYSTEMABILITYTASK_ID = 18,

    NAPI_ON_SESSION_DESTROY_TASK_ID,
    NAPI_ON_PLAYBACK_STATE_CHANGE_TASK_ID,
    NAPI_ON_META_DATA_CHANGE_TASK_ID,
    NAPI_ON_ACTIVE_STATE_CHANGE_TASK_ID,
    NAPI_ON_VALID_COMMAND_CHANGE_TASK_ID,
    NAPI_ON_PLAY_TASK_ID,
    NAPI_ON_PAUSE_TASK_ID,
    NAPI_ON_STOP_TASK_ID,
    NAPI_ON_PLAY_NEXT_TASK_ID,
    NAPI_ON_PLAY_PREVIOUS_TASK_ID,
    NAPI_ON_FAST_FORWARD_TASK_ID,
    NAPI_ON_REWIND_TASK_ID,
    NAPI_ON_SEEK_TASK_ID,
    NAPI_ON_SET_SPEED_TASK_ID,
    NAPI_ON_SET_LOOP_MODE_TASK_ID,
    NAPI_ON_TOGGLE_FAVORITE_TASK_ID,
    NAPI_ON_MEDIA_KEY_EVENT_TASK_ID,
    NAPI_ON_SESSION_CREATE_TASK_ID,
    NAPI_ON_SESSION_RELEASE_TASK_ID,
    NAPI_ON_TOP_SESSION_CHANGED_TASK_ID,
    NAPI_ON_SESSION_SERVICE_DIED_TASK_ID,

    NAPI_SET_AV_META_DATA_TASK_ID,
    NAPI_SET_AV_PLAYBACK_STATE_TASK_ID,
    NAPI_SET_LAUNCH_ABILITY_TASK_ID,
    NAPI_GET_CONTROLLER_TASK_ID,
    NAPI_ACTIVATE_TASK_ID,
    NAPI_DEACTIVATE_TASK_ID,
    NAPI_AVSESSION_DESTROY_TASK_ID,
    NAPI_SET_AUDIO_STREAM_ID_TASK_ID,
    NAPI_AVSESSION_GET_OUTPUT_DEVICE_TASK_ID,
    NAPI_GET_AV_PLAYBACK_STATE_TASK_ID,
    NAPI_GET_AV_META_DATA_TASK_ID,
    NAPI_SEND_AV_KEY_EVENT_TASK_ID,
    NAPI_GET_LAUNCH_ABILITY_TASK_ID,
    NAPI_IS_ACTIVE_TASK_ID,
    NAPI_AVSESSION_CONTROLLER_DESTROY_TASK_ID,
    NAPI_GET_VALID_COMMANDS_TASK_ID,
    NAPI_SEND_CONTROL_COMMAND_TASK_ID,
    NAPI_AVSESSION_CONTROLLER_GET_OUTPUT_DEVICE_TASK_ID,
    NAPI_CREATE_AVSESSION_TASK_ID,
    NAPI_GET_ALL_SESSION_DESCRIPTORS_TASK_ID,
    NAPI_CREATE_CONTROLLER_TASK_ID,
    NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID,
    NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID,
    NAPI_CAST_AUDIO_TASK_ID,
};

class __attribute__((visibility("default"))) AVSessionTrace {
public:
    explicit AVSessionTrace(const std::string& funcName)
    {
        std::string avSessionTrace("AVSession:");
        avSessionTrace += funcName;
        StartTrace(HITRACE_TAG_ZMEDIA, avSessionTrace);
        isSync_ = true;
    }

    static void TraceBegin(const std::string& funcName, int32_t taskId)
    {
        std::string traceBegin("AVSession:");
        traceBegin += funcName;
        StartAsyncTrace(HITRACE_TAG_ZMEDIA, traceBegin, taskId);
    }

    static void TraceEnd(const std::string& funcName, int32_t taskId)
    {
        std::string traceEnd("AVSession:");
        traceEnd += funcName;
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