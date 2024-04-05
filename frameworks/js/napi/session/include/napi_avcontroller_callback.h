/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_AVCONTROLLER_CALLBACK_H
#define OHOS_NAPI_AVCONTROLLER_CALLBACK_H

#include <list>
#include "avsession_info.h"
#include "avsession_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"

namespace OHOS::AVSession {
class NapiAVControllerCallback : public AVControllerCallback {
public:
    enum {
        EVENT_SESSION_DESTROY,
        EVENT_PLAYBACK_STATE_CHANGE,
        EVENT_META_DATA_CHANGE,
        EVENT_ACTIVE_STATE_CHANGE,
        EVENT_VALID_COMMAND_CHANGE,
        EVENT_OUTPUT_DEVICE_CHANGE,
        EVENT_SESSION_EVENT_CHANGE,
        EVENT_QUEUE_ITEMS_CHANGE,
        EVENT_QUEUE_TITLE_CHANGE,
        EVENT_EXTRAS_CHANGE,
        EVENT_AVCALL_META_DATA_CHANGE,
        EVENT_AVCALL_STATE_CHANGE,
        EVENT_TYPE_MAX,
    };

    NapiAVControllerCallback();
    ~NapiAVControllerCallback() override;

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

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);
    void AddCallbackForSessionDestroy(const std::function<void(void)>& sessionDestroyCallback);

private:
    void HandleEvent(int32_t event);

    template<typename T>
    void HandleEvent(int32_t event, const T& param);

    template<typename T>
    void HandleEvent(int32_t event, const std::string& firstParam, const T& secondParam);

    template<typename T>
    void HandleEvent(int32_t event, const int32_t firstParam, const T& secondParam);

    template<typename T>
    void HandleEventWithOrder(int32_t event, int state, const T& param);

    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    std::list<napi_ref> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;
    std::function<void(void)> sessionDestroyCallback_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCONTROLLER_CALLBACK_H