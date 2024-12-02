/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_CJ_AVSESSION_CONTROLLER_CALLBACK_H
#define OHOS_CJ_AVSESSION_CONTROLLER_CALLBACK_H

#include <cstdint>
#include <list>
#include <vector>
#include <map>

#include "avsession_controller.h"
#include "avsession_info.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {
class CJAVControllerCallback : public AVControllerCallback {
public:
    CJAVControllerCallback();
    ~CJAVControllerCallback() = default;
    static int32_t OffEvent(int32_t type);
    void OnAVCallMetaDataChange(const AVCallMetaData& avCallMetaData) override;
    void OnAVCallStateChange(const AVCallState& avCallState) override;
    void OnSessionDestroy() override;
    void OnPlaybackStateChange(const AVPlaybackState& state) override;
    void OnMetaDataChange(const AVMetaData& data) override;
    void OnActiveStateChange(bool isActive) override;
    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& info) override;
    void OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args) override;
    void OnQueueItemsChange(const std::vector<AVQueueItem>& items) override;
    void OnQueueTitleChange(const std::string& title) override;
    void OnExtrasChange(const AAFwk::WantParams& extras) override;

    void RegisterCallback(int32_t type, int64_t id);
    void UnRegisterCallback(int32_t type);

private:
    void InitOnAVCallMetaDataChange(int64_t id);
    void InitOnAVCallStateChange(int64_t id);
    void InitOnSessionDestroy(int64_t id);
    void InitOnPlaybackStateChange(int64_t id);
    void InitOnMetaDataChange(int64_t id);
    void InitOnActiveStateChange(int64_t id);
    void InitOnValidCommandChange(int64_t id);
    void InitOnOutputDeviceChange(int64_t id);
    void InitOnSessionEventChange(int64_t id);
    void InitOnQueueItemsChange(int64_t id);
    void InitOnQueueTitleChange(int64_t id);
    void InitOnExtrasChange(int64_t id);
    std::function<void(const CAVCallMetaData)> onAVCallMetaDataChange;
    std::function<void(const CAVCallState)> onAVCallStateChange;
    std::function<void(void)> onSessionDestroy;
    std::function<void(const CAVPlaybackState)> onPlaybackStateChange;
    std::function<void(const CAVMetaData)> onMetaDataChange;
    std::function<void(bool)> onActiveStateChange;
    std::function<void(CArray)> onValidCommandChange;
    std::function<void(const int32_t, COutputDeviceInfo)> onOutputDeviceChange;
    std::function<void(const char*, CArray)> onSessionEventChange;
    std::function<void(CArray)> onQueueItemsChange; //CArray* items
    std::function<void(const char* title)> onQueueTitleChange;
    std::function<void(CArray)> onExtrasChange;
    std::map<int32_t, void(CJAVControllerCallback::*)(int64_t)> typeToCallbackMap_;
    std::vector<std::shared_ptr<std::recursive_mutex>> callbackMutexMap_;
};
} // namespace OHOS::AVSession
#endif // OHOS_CJ_AVSESSION_CONTROLLER_CALLBACK_H