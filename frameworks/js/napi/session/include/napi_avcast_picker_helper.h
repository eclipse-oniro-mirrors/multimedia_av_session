/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_AVCAST_PICKER_HELPER_H
#define OHOS_NAPI_AVCAST_PICKER_HELPER_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "avsession_log.h"
#include "napi_async_callback.h"
#include "ui_content.h"
#include "ui_extension_context.h"
#include "audio_routing_manager.h"

namespace OHOS::AVSession {

struct PickerCallBack {
    bool ready = false;
    int32_t resultCode;
};

class ModalUICallback {
public:
    explicit ModalUICallback(Ace::UIContent* uiContent, PickerCallBack& pickerCallBack);
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();

private:
    int32_t sessionId_ = 0;
    Ace::UIContent* uiContent_;
    PickerCallBack pickerCallBack_;
};

struct NapiAVCastPickerOptions {
    std::string sessionType = "audio";
};

class NapiAVCastPickerHelper {
public:
    enum {
        EVENT_PICPKER_STATE_CHANGE,
        EVENT_TYPE_MAX
    };

    static napi_value Init(napi_env env, napi_value exports);

    using OnEventHandlerType = std::function<napi_status(napi_env, NapiAVCastPickerHelper*, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, NapiAVCastPickerHelper*, napi_value)>;

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event, napi_value callback);

    bool IsCallbacksEmpty(int32_t event);

private:
    explicit NapiAVCastPickerHelper(Ace::UIContent* uiContent);
    ~NapiAVCastPickerHelper();

    static napi_value ConstructorCallback(napi_env env, napi_callback_info info);

    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_value SelectAVPicker(napi_env env, napi_callback_info info);
    static napi_value RestoreDefaultCommunicationDevice(napi_env env, napi_callback_info info);

    static napi_status OnPickerStateChange(napi_env env, NapiAVCastPickerHelper* napiAVPicker, napi_value callback);
    static napi_status OffPickerStateChange(napi_env env, NapiAVCastPickerHelper* napiAVPicker, napi_value callback);

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;

    template<typename T>
    void HandleEvent(int32_t event, const T& param);
    
    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    std::list<napi_ref> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;

    Ace::UIContent *uiContent_;
    napi_ref wrapperRef_{};
    int sessionId_ = 0;

    AudioStandard::AudioRoutingManager *audioRoutingMngr_;

    static constexpr size_t ARGC_ZERO = 0;
    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THREE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;

    static constexpr uint32_t STATE_APPEARING = 0;
    static constexpr uint32_t STATE_DISAPPEARING = 1;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCAST_PICKER_HELPER_H
