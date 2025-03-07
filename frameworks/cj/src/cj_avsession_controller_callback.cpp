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
#include <string>

#include "cj_avsession_controller_callback.h"
#include "avsession_log.h"
#include "cj_lambda.h"
#include "cj_avsession_utils.h"

namespace OHOS::AVSession {
const int32_t SESSION_DESTROY = 0;
const int32_t PLAYBACK_STATE_CHANGE = 1;
const int32_t META_DATA_CHANGE = 2;
const int32_t ACTIVE_STATE_CHANGE = 3;
const int32_t VALID_COMMAND_CHANGE = 4;
const int32_t OUTPUT_DEVICE_CHANGE = 5;
const int32_t SESSION_EVENT_CHANGE = 6;
const int32_t QUEUE_ITEMS_CHANGE = 7;
const int32_t QUEUE_TITLE_CHANGE = 8;
const int32_t EXTRAS_CHANGE = 9;
const int32_t AVCALL_META_DATA_CHANGE = 10;
const int32_t AVCALL_STATE_CHANGE = 11;
const int32_t MAX_EVENT_NUM = 12;

CJAVControllerCallback::CJAVControllerCallback()
{
    typeToCallbackMap_[PLAYBACK_STATE_CHANGE] = &CJAVControllerCallback::InitOnPlaybackStateChange;
    typeToCallbackMap_[META_DATA_CHANGE] = &CJAVControllerCallback::InitOnMetaDataChange;
    typeToCallbackMap_[ACTIVE_STATE_CHANGE] = &CJAVControllerCallback::InitOnActiveStateChange;
    typeToCallbackMap_[AVCALL_META_DATA_CHANGE] = &CJAVControllerCallback::InitOnAVCallMetaDataChange;
    typeToCallbackMap_[AVCALL_STATE_CHANGE] = &CJAVControllerCallback::InitOnAVCallStateChange;
    typeToCallbackMap_[SESSION_DESTROY] = &CJAVControllerCallback::InitOnSessionDestroy;
    typeToCallbackMap_[VALID_COMMAND_CHANGE] = &CJAVControllerCallback::InitOnValidCommandChange;
    typeToCallbackMap_[OUTPUT_DEVICE_CHANGE] = &CJAVControllerCallback::InitOnOutputDeviceChange;
    typeToCallbackMap_[SESSION_EVENT_CHANGE] = &CJAVControllerCallback::InitOnSessionEventChange;
    typeToCallbackMap_[QUEUE_ITEMS_CHANGE] = &CJAVControllerCallback::InitOnQueueItemsChange;
    typeToCallbackMap_[QUEUE_TITLE_CHANGE] = &CJAVControllerCallback::InitOnQueueTitleChange;
    typeToCallbackMap_[EXTRAS_CHANGE] = &CJAVControllerCallback::InitOnExtrasChange;
    for (uint32_t i = 0; i < MAX_EVENT_NUM; i++) {
        callbackMutexMap_.push_back(std::make_shared<std::recursive_mutex>());
    }
}

void CJAVControllerCallback::RegisterCallback(int32_t type, int64_t id)
{
    if (typeToCallbackMap_.count(type) > 0) {
        std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[type]);
        (this->*(typeToCallbackMap_[type]))(id);
    } else {
        SLOGE("INVALID EVENT TYPE");
    }
}
void CJAVControllerCallback::UnRegisterCallback(int32_t type)
{
    if (typeToCallbackMap_.count(type) > 0) {
        std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[type]);
        (this->*(typeToCallbackMap_[type]))(0);
    } else {
        SLOGE("INVALID EVENT TYPE");
    }
}
void CJAVControllerCallback::InitOnAVCallMetaDataChange(int64_t id)
{
    if (id == 0) {
        onAVCallMetaDataChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CAVCallMetaData)>(id);
    onAVCallMetaDataChange = [lambda = CJLambda::Create(callback)](CAVCallMetaData cAvCallMetaData) -> void {
        lambda(cAvCallMetaData);
    };
}

void CJAVControllerCallback::InitOnAVCallStateChange(int64_t id)
{
    if (id == 0) {
        onAVCallStateChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CAVCallState)>(id);
    onAVCallStateChange = [lambda = CJLambda::Create(callback)](CAVCallState cAvCallstate) -> void {
        lambda(cAvCallstate);
    };
}

void CJAVControllerCallback::InitOnSessionDestroy(int64_t id)
{
    if (id == 0) {
        onSessionDestroy = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(void)>(id);
    onSessionDestroy = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJAVControllerCallback::InitOnPlaybackStateChange(int64_t id)
{
    if (id == 0) {
        onPlaybackStateChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CAVPlaybackState)>(id);
    onPlaybackStateChange = [lambda = CJLambda::Create(callback)](CAVPlaybackState cAvPlaybackState) -> void {
        lambda(cAvPlaybackState);
    };
}

void CJAVControllerCallback::InitOnMetaDataChange(int64_t id)
{
    if (id == 0) {
        onMetaDataChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CAVMetaData)>(id);
    onMetaDataChange = [lambda = CJLambda::Create(callback)](CAVMetaData cAvMetaData) -> void {
        lambda(cAvMetaData);
    };
}
void CJAVControllerCallback::InitOnActiveStateChange(int64_t id)
{
    if (id == 0) {
        onActiveStateChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(bool)>(id);
    onActiveStateChange = [lambda = CJLambda::Create(callback)](bool isActive) -> void {
        lambda(isActive);
    };
}
void CJAVControllerCallback::InitOnValidCommandChange(int64_t id)
{
    if (id == 0) {
        onValidCommandChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CArray)>(id);
    onValidCommandChange = [lambda = CJLambda::Create(callback)](CArray cmds) -> void {
        lambda(cmds);
    };
}

void CJAVControllerCallback::InitOnOutputDeviceChange(int64_t id)
{
    if (id == 0) {
        onOutputDeviceChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const int32_t, COutputDeviceInfo)>(id);
    onOutputDeviceChange = [lambda = CJLambda::Create(callback)](
        const int32_t connectionState, COutputDeviceInfo cOutputDeviceInfo) -> void {
        lambda(connectionState, cOutputDeviceInfo);
    };
}

void CJAVControllerCallback::InitOnSessionEventChange(int64_t id)
{
    if (id == 0) {
        onSessionEventChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const char*, CArray)>(id);
    onSessionEventChange = [lambda = CJLambda::Create(callback)](const char* event, CArray args) -> void {
        lambda(event, args);
    };
}

void CJAVControllerCallback::InitOnQueueItemsChange(int64_t id)
{
    if (id == 0) {
        onQueueItemsChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CArray)>(id);
    onQueueItemsChange = [lambda = CJLambda::Create(callback)](CArray items) -> void {
        lambda(items);
    };
}

void CJAVControllerCallback::InitOnQueueTitleChange(int64_t id)
{
    if (id == 0) {
        onQueueTitleChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(const char*)>(id);
    onQueueTitleChange = [lambda = CJLambda::Create(callback)](const char* title) -> void {
        lambda(title);
    };
}

void CJAVControllerCallback::InitOnExtrasChange(int64_t id)
{
    if (id == 0) {
        onExtrasChange = nullptr;
        return;
    }
    auto callback = reinterpret_cast<void(*)(CArray)>(id);
    onExtrasChange = [lambda = CJLambda::Create(callback)](CArray extras) -> void {
        lambda(extras);
    };
}

void CJAVControllerCallback::OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[AVCALL_META_DATA_CHANGE]);
    if (onAVCallMetaDataChange == nullptr) {
        SLOGD("onAVCallMetaDataChange null");
        return;
    }
    CAVCallMetaData cAvCallMetaData {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(avCallMetaData, cAvCallMetaData);
    if (ret != CJNO_ERROR) {
        cjStructHeapFree(cAvCallMetaData);
        return;
    }
    SLOGD("onAVCallMetaDataChange runs");
    onAVCallMetaDataChange(cAvCallMetaData);
    cjStructHeapFree(cAvCallMetaData);
}

void CJAVControllerCallback::OnAVCallStateChange(const AVCallState& avCallState)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[AVCALL_STATE_CHANGE]);
    if (onAVCallStateChange == nullptr) {
        SLOGD("onAVCallStateChange null");
        return;
    }
    CAVCallState cAvCallState;
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(avCallState, cAvCallState);
    if (ret != CJNO_ERROR) {
        return;
    }
    SLOGD("onAVCallStateChange runs");
    onAVCallStateChange(cAvCallState);
}

void CJAVControllerCallback::OnSessionDestroy()
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SESSION_DESTROY]);
    if (onSessionDestroy == nullptr) {
        SLOGD("onSessionDestroy null");
        return;
    }
    SLOGD("onSessionDestroy runs");
    onSessionDestroy();
}

void CJAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[PLAYBACK_STATE_CHANGE]);
    if (onPlaybackStateChange == nullptr) {
        SLOGD("onPlaybackStateChange null");
        return;
    }
    CAVPlaybackState cAvPlaybackState {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(state, cAvPlaybackState);
    if (ret != CJNO_ERROR) {
        cjStructHeapFree(cAvPlaybackState);
        return;
    }
    SLOGD("onPlaybackStateChange runs");
    onPlaybackStateChange(cAvPlaybackState);
    cjStructHeapFree(cAvPlaybackState);
}

void CJAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[META_DATA_CHANGE]);
    if (onMetaDataChange == nullptr) {
        SLOGD("onMetaDataChange null");
        return;
    }
    CAVMetaData cAvMetaData {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(data, cAvMetaData);
    if (ret != CJNO_ERROR) {
        cjStructHeapFree(cAvMetaData);
        return;
    }
    SLOGD("onMetaDataChange runs");
    onMetaDataChange(cAvMetaData);
    cjStructHeapFree(cAvMetaData);
}

void CJAVControllerCallback::OnActiveStateChange(bool isActive)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[ACTIVE_STATE_CHANGE]);
    if (onActiveStateChange == nullptr) {
        SLOGD("onActiveStateChange null");
        return;
    }
    SLOGD("onActiveStateChange runs");
    onActiveStateChange(isActive);
}

void CJAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[VALID_COMMAND_CHANGE]);
    if (onValidCommandChange == nullptr) {
        SLOGD("onValidCommandChange null");
        return;
    }
    CArray cCmds {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(cmds, cCmds);
    if (ret != CJNO_ERROR) {
        cjStructHeapFree(cCmds);
        return;
    }
    SLOGD("onValidCommandChange runs");
    onValidCommandChange(cCmds);
    cjStructHeapFree(cCmds);
}

void CJAVControllerCallback::OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& info)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[OUTPUT_DEVICE_CHANGE]);
    if (onOutputDeviceChange == nullptr) {
        SLOGD("onOutputDeviceChange null");
        return;
    }
    COutputDeviceInfo cOutputDeviceInfo {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(info, cOutputDeviceInfo);
    if (ret != CJNO_ERROR) {
        cjStructHeapFree(cOutputDeviceInfo);
        return;
    }
    SLOGD("onOutputDeviceChange runs");
    onOutputDeviceChange(connectionState, cOutputDeviceInfo);
    cjStructHeapFree(cOutputDeviceInfo);
}

void CJAVControllerCallback::OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[SESSION_EVENT_CHANGE]);
    SLOGD("session event changed");
    if (onSessionEventChange == nullptr) {
        SLOGD("onSessionEventChange null");
        return;
    }
    int ret = CJNO_ERROR;
    char* cEvent = nullptr;
    ret = ConvertNativeToCJStruct(event, cEvent);
    if (ret != CJNO_ERROR) {
        SLOGD("std::string convert to c_str failed");
        return ;
    }
    
    CArray cArgs {};
    ret = ConvertNativeToCJStruct(args, cArgs);
    if (ret != CJNO_ERROR) {
        free(cEvent);
        cjStructHeapFreeWant(cArgs);
        SLOGD("AAFwk::WantParams convert to C Type failed");
        return ;
    }
    onSessionEventChange(cEvent, cArgs);
    free(cEvent);
    cjStructHeapFreeWant(cArgs);
}

void CJAVControllerCallback::OnQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[QUEUE_ITEMS_CHANGE]);
    if (onQueueItemsChange == nullptr) {
        SLOGD("onQueueItemsChange null");
        return;
    }
    CArray cQueueItems {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(items, cQueueItems);
    if (ret != CJNO_ERROR) {
        cjStructHeapFreeAVQueueItem(cQueueItems);
        return;
    }
    SLOGD("onQueueItemsChange runs");
    onQueueItemsChange(cQueueItems);
    cjStructHeapFreeAVQueueItem(cQueueItems);
}

void CJAVControllerCallback::OnQueueTitleChange(const std::string& title)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[QUEUE_TITLE_CHANGE]);
    if (onQueueTitleChange == nullptr) {
        SLOGD("onQueueTitleChange null");
        return;
    }
    SLOGD("onQueueTitleChange runs");
    onQueueTitleChange(title.c_str());
}

void CJAVControllerCallback::OnExtrasChange(const AAFwk::WantParams& extras)
{
    std::lock_guard<std::recursive_mutex> lock(*callbackMutexMap_[EXTRAS_CHANGE]);
    if (onExtrasChange == nullptr) {
        SLOGD("onExtrasChange null");
        return;
    }
    CArray cExtras {};
    int ret = CJNO_ERROR;
    ret = ConvertNativeToCJStruct(extras, cExtras);
    if (ret != CJNO_ERROR) {
        cjStructHeapFreeWant(cExtras);
        return;
    }
    SLOGD("onExtrasChange runs");
    onExtrasChange(cExtras);
    cjStructHeapFreeWant(cExtras);
}
};