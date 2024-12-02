/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <cstdint>

#include "avsession_log.h"
#include "cj_avsession_callback.h"
#include "cj_lambda.h"
#include "cj_avsession_utils.h"

namespace OHOS::AVSession {
const int8_t PLAY = 0;
const int8_t PAUSE = 1;
const int8_t STOP = 2;
const int8_t PLAY_NEXT = 3;
const int8_t PLAY_PREVIOUS = 4;
const int8_t FAST_FORWARD = 5;
const int8_t REWIND = 6;
const int8_t PLAY_FROM_ASSET_ID = 7;
const int8_t SEEK = 8;
const int8_t SET_SPEED = 9;
const int8_t SET_LOOP_MODE = 10;
const int8_t TOGGLE_FAVORITE = 11;
const int8_t SKIP_TO_QUEUE_ITEM = 12;
const int8_t HANDLE_KEY_EVENT = 13;
const int8_t OUTPUT_DEVICE_CHANGE = 14;
const int8_t COMMON_COMMAND = 15;
const int8_t ANSWER = 16;
const int8_t HANG_UP = 17;
const int8_t TOGGLE_CALL_MUTE = 18;
const int8_t CAST_DISPLAY_CHANGE = 19;
const int8_t MAX_EVENT_NUM = 20;

CJAVSessionCallback::CJAVSessionCallback()
{
    typeToCallbackMap_[PLAY] = &CJAVSessionCallback::InitPlay;
    typeToCallbackMap_[PAUSE] = &CJAVSessionCallback::InitPause;
    typeToCallbackMap_[STOP] = &CJAVSessionCallback::InitStop;
    typeToCallbackMap_[PLAY_NEXT] = &CJAVSessionCallback::InitPlayNext;
    typeToCallbackMap_[PLAY_PREVIOUS] = &CJAVSessionCallback::InitPlayPrevious;
    typeToCallbackMap_[FAST_FORWARD] = &CJAVSessionCallback::InitFastForward;
    typeToCallbackMap_[REWIND] = &CJAVSessionCallback::InitRewind;
    typeToCallbackMap_[PLAY_FROM_ASSET_ID] = &CJAVSessionCallback::InitPlayFromAssetId;
    typeToCallbackMap_[SEEK] = &CJAVSessionCallback::InitSeek;
    typeToCallbackMap_[SET_SPEED] = &CJAVSessionCallback::InitSetSpeed;
    typeToCallbackMap_[SET_LOOP_MODE] = &CJAVSessionCallback::InitSetLoopMode;
    typeToCallbackMap_[TOGGLE_FAVORITE] = &CJAVSessionCallback::InitToggleFavorite;
    typeToCallbackMap_[SKIP_TO_QUEUE_ITEM] = &CJAVSessionCallback::InitSkipToQueueItem;
    typeToCallbackMap_[HANDLE_KEY_EVENT] = &CJAVSessionCallback::InitHandleKeyEvent;
    typeToCallbackMap_[OUTPUT_DEVICE_CHANGE] = &CJAVSessionCallback::InitOutputDeviceChange;
    typeToCallbackMap_[COMMON_COMMAND] = &CJAVSessionCallback::InitCommonCommand;
    typeToCallbackMap_[ANSWER] = &CJAVSessionCallback::InitAnswer;
    typeToCallbackMap_[HANG_UP] = &CJAVSessionCallback::InitHangUp;
    typeToCallbackMap_[TOGGLE_CALL_MUTE] = &CJAVSessionCallback::InitToggleCallMute;
    typeToCallbackMap_[CAST_DISPLAY_CHANGE] = &CJAVSessionCallback::InitCastDisplayChange;
    for (uint32_t i = 0; i < MAX_EVENT_NUM; i++) {
        callbackMutexMap_.push_back(std::make_shared<std::recursive_mutex>());
    }
}

void CJAVSessionCallback::RegisterCallback(int32_t type, int64_t id)
{
    if (typeToCallbackMap_.count(type) > 0) {
        std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[type]);
        (this->*(typeToCallbackMap_[type]))(id);
    } else {
        SLOGE("INVALID EVENT TYPE");
    }
}

void CJAVSessionCallback::UnRegisterCallback(int32_t type)
{
    if (typeToCallbackMap_.count(type) > 0) {
        std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[type]);
        (this->*(typeToCallbackMap_[type]))(0);
    } else {
        SLOGE("INVALID EVENT TYPE");
    }
}

void CJAVSessionCallback::InitPlay(int64_t id)
{
    if (id == 0) {
        play = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    play = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitPause(int64_t id)
{
    if (id == 0) {
        pause = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    pause = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitStop(int64_t id)
{
    if (id == 0) {
        stop = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    stop = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitPlayNext(int64_t id)
{
    if (id == 0) {
        playNext = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    playNext = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitPlayPrevious(int64_t id)
{
    if (id == 0) {
        playPrevious = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    playPrevious = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitFastForward(int64_t id)
{
    if (id == 0) {
        fastForward = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int64_t)>(id);
    fastForward = [lambda = CJLambda::Create(callback)](int64_t time) -> void {
        lambda(time);
    };
}

void CJAVSessionCallback::InitRewind(int64_t id)
{
    if (id == 0) {
        rewind = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int64_t)>(id);
    rewind = [lambda = CJLambda::Create(callback)](int64_t time) -> void {
        lambda(time);
    };
}

void CJAVSessionCallback::InitPlayFromAssetId(int64_t id)
{
    if (id == 0) {
        playFromAssetId = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int64_t)>(id);
    playFromAssetId = [lambda = CJLambda::Create(callback)](int64_t assetId) -> void {
        lambda(assetId);
    };
}

void CJAVSessionCallback::InitSeek(int64_t id)
{
    if (id == 0) {
        seek = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int64_t)>(id);
    seek = [lambda = CJLambda::Create(callback)](int64_t time) -> void {
        lambda(time);
    };
}

void CJAVSessionCallback::InitSetSpeed(int64_t id)
{
    if (id == 0) {
        setSpeed = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(double)>(id);
    setSpeed = [lambda = CJLambda::Create(callback)](double speed) -> void {
        lambda(speed);
    };
}

void CJAVSessionCallback::InitSetLoopMode(int64_t id)
{
    if (id == 0) {
        setLoopMode = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    setLoopMode = [lambda = CJLambda::Create(callback)](int32_t loopMode) -> void {
        lambda(loopMode);
    };
}

void CJAVSessionCallback::InitToggleFavorite(int64_t id)
{
    if (id == 0) {
        toggleFavorite = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const char*)>(id);
    toggleFavorite = [lambda = CJLambda::Create(callback)](const char* assetId) -> void {
        lambda(assetId);
    };
}

void CJAVSessionCallback::InitSkipToQueueItem(int64_t id)
{
    if (id == 0) {
        skipToQueueItem = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(int32_t)>(id);
    skipToQueueItem = [lambda = CJLambda::Create(callback)](int32_t itemId) -> void {
        lambda(itemId);
    };
}

void CJAVSessionCallback::InitHandleKeyEvent(int64_t id)
{
    if (id == 0) {
        handleKeyEvent = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CKeyEvent)>(id);
    handleKeyEvent = [lambda = CJLambda::Create(callback)](CKeyEvent event) -> void {
        lambda(event);
    };
}

void CJAVSessionCallback::InitOutputDeviceChange(int64_t id)
{
    if (id == 0) {
        outputDeviceChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const int32_t, COutputDeviceInfo)>(id);
    outputDeviceChange = [lambda = CJLambda::Create(callback)](
        const int32_t connectionState, COutputDeviceInfo deviceInfo) -> void {
        lambda(connectionState, deviceInfo);
    };
}

void CJAVSessionCallback::InitCommonCommand(int64_t id)
{
    if (id == 0) {
        commonCommand = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const char*, CArray)>(id);
    commonCommand = [lambda = CJLambda::Create(callback)](const char* command, CArray obj) -> void {
        lambda(command, obj);
    };
}

void CJAVSessionCallback::InitAnswer(int64_t id)
{
    if (id == 0) {
        answer = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    answer = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitHangUp(int64_t id)
{
    if (id == 0) {
        hangUp = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    hangUp = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitToggleCallMute(int64_t id)
{
    if (id == 0) {
        toggleCallMute = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)()>(id);
    toggleCallMute = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVSessionCallback::InitCastDisplayChange(int64_t id)
{
    if (id == 0) {
        castDisplayChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CCastDisplayInfo)>(id);
    castDisplayChange = [lambda = CJLambda::Create(callback)](CCastDisplayInfo cdisplayInfo) -> void {
        lambda(cdisplayInfo);
    };
}


void CJAVSessionCallback::OnPlay()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PLAY]);
    if (play) {
        SLOGD("play runs");
        play();
    }
}

void CJAVSessionCallback::OnPause()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PAUSE]);
    if (pause) {
        SLOGD("pause runs");
        pause();
    }
}

void CJAVSessionCallback::OnStop()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[STOP]);
    if (stop) {
        SLOGD("stop runs");
        stop();
    }
}

void CJAVSessionCallback::OnPlayNext()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PLAY_NEXT]);
    if (playNext) {
        SLOGD("play next runs");
        playNext();
    }
}

void CJAVSessionCallback::OnPlayPrevious()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PLAY_PREVIOUS]);
    if (playPrevious) {
        SLOGD("play previous runs");
        playPrevious();
    }
}

void CJAVSessionCallback::OnFastForward(int64_t time)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[FAST_FORWARD]);
    if (fastForward) {
        SLOGD("fast forward by %" PRIi64 " ms", time);
        fastForward(time);
    }
}

void CJAVSessionCallback::OnRewind(int64_t time)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[REWIND]);
    if (rewind) {
        SLOGD("rewind by %" PRIi64 " ms", time);
        rewind(time);
    }
}

void CJAVSessionCallback::OnSeek(int64_t time)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SEEK]);
    if (seek) {
        SLOGD("seek to %" PRIi64 " ms", time);
        seek(time);
    }
}

void CJAVSessionCallback::OnSetSpeed(double speed)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SET_SPEED]);
    if (setSpeed) {
        SLOGD("set speed to %f", speed);
        setSpeed(speed);
    }
    }

void CJAVSessionCallback::OnSetLoopMode(int32_t loopMode)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SET_LOOP_MODE]);
    if (setLoopMode) {
        SLOGD("set loop mode to %d", loopMode);
        setLoopMode(loopMode);
    }
}

void CJAVSessionCallback::OnToggleFavorite(const std::string& assertId)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[TOGGLE_FAVORITE]);
    if (toggleFavorite) {
        SLOGD("toggle favorite for assertId: %s", assertId.c_str());
        int ret = CJNO_ERROR;
        char* cassertId = nullptr;
        ret = convertNativeToCJStruct(assertId, cassertId);
        if (ret != CJNO_ERROR) {
            SLOGD("std::string convert to C Type failed");
            return ;
        }
        toggleFavorite(cassertId);
        free(cassertId);
    }
}

void CJAVSessionCallback::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[HANDLE_KEY_EVENT]);
    if (handleKeyEvent) {
        SLOGD("media key event received");
        CKeyEvent ckeyEvent;
        int ret = CJNO_ERROR;
        ret = convertNativeToCJStruct(keyEvent, ckeyEvent);
        if (ret != CJNO_ERROR) {
            SLOGD("KeyEvent convert to C Type failed");
            return ;
        }
        handleKeyEvent(ckeyEvent);
        free(ckeyEvent.keys);
    }
}

void CJAVSessionCallback::OnOutputDeviceChange(
    const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[OUTPUT_DEVICE_CHANGE]);
    if (outputDeviceChange) {
        SLOGD("output device connection state: %d", connectionState);
        COutputDeviceInfo coutputDeviceInfo;
        int ret = CJNO_ERROR;
        ret = convertNativeToCJStruct(outputDeviceInfo, coutputDeviceInfo);
        if (ret != CJNO_ERROR) {
            SLOGD("OutputDeviceInfo convert to C Type failed");
            return ;
        }
        outputDeviceChange(connectionState, coutputDeviceInfo);
        cjStructHeapFree(coutputDeviceInfo);
    }
}

void CJAVSessionCallback::OnCommonCommand(
    const std::string& command, const AAFwk::WantParams& commandArgs)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[COMMON_COMMAND]);
    if (commonCommand) {
        SLOGD("common command received");
        int ret = CJNO_ERROR;
        char* ccommand = nullptr;
        ret = convertNativeToCJStruct(command, ccommand);
        if (ret != CJNO_ERROR) {
            SLOGD("std::string convert to c_str failed");
            return ;
        }
        SLOGD("common command received: %s", ccommand);
        CArray cArgs;
        ret = convertNativeToCJStruct(commandArgs, cArgs);
        if (ret != CJNO_ERROR) {
            SLOGD("AAFwk::WantParams convert to C Type failed");
            return ;
        }
        commonCommand(ccommand, cArgs);
        free(ccommand);
        cjStructHeapFree(cArgs);
    }
}

void CJAVSessionCallback::OnSkipToQueueItem(int32_t itemId)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SKIP_TO_QUEUE_ITEM]);
    if (skipToQueueItem) {
        SLOGD("skip to queue item %d", itemId);
        skipToQueueItem(itemId);
    }
}

void CJAVSessionCallback::OnAVCallAnswer()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[ANSWER]);
    if (answer) {
        SLOGD("AV call answered");
        answer();
    }
}

void CJAVSessionCallback::OnAVCallHangUp()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[HANG_UP]);
    if (hangUp) {
        SLOGD("AV call hung up");
        hangUp();
    }
}

void CJAVSessionCallback::OnAVCallToggleCallMute()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[TOGGLE_CALL_MUTE]);
    if (toggleCallMute) {
        SLOGD("AV call toggle mute");
        toggleCallMute();
    }
}

void CJAVSessionCallback::OnPlayFromAssetId(int64_t assetId)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PLAY_FROM_ASSET_ID]);
    if (playFromAssetId) {
        SLOGD("play from asset id: %" PRId64 "", assetId);
        playFromAssetId(assetId);
    }
}

void CJAVSessionCallback::OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[CAST_DISPLAY_CHANGE]);
    if (castDisplayChange) {
        SLOGD("cast display change");
        CCastDisplayInfo ccastDisplayInfo;
        int ret = CJNO_ERROR;
        ret = convertNativeToCJStruct(castDisplayInfo, ccastDisplayInfo);
        if (ret != CJNO_ERROR) {
            SLOGD("CastDisplayInfo convert to C Type failed");
            return ;
        }
        castDisplayChange(ccastDisplayInfo);
        cjStructHeapFree(ccastDisplayInfo);
    }
}
} // end of avsession namespace