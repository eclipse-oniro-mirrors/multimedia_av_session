/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TAIHE_AVCAST_PICKER_HELPER_H
#define TAIHE_AVCAST_PICKER_HELPER_H

#include "ui_content.h"
#include "ui_extension_context.h"
#include "taihe_async_callback.h"
#include "event_handler.h"
#include "ohos.multimedia.avCastPickerParam.impl.hpp"
#include "ohos.multimedia.avCastPickerParam.proj.hpp"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;
using namespace ohos::multimedia::avCastPickerParam;

struct PickerCallBack {
    bool ready = false;
    int32_t resultCode = OHOS::AVSession::AVSESSION_ERROR;
};

class ModalUICallback {
public:
    explicit ModalUICallback(OHOS::Ace::UIContent* uiContent, PickerCallBack& pickerCallBack);
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();

private:
    int32_t sessionId_ = 0;
    OHOS::Ace::UIContent* uiContent_;
    PickerCallBack pickerCallBack_;
};

struct TaiheAVCastPickerOptions {
    std::string sessionType = "audio";
};

class AVCastPickerHelperInnerImpl {
public:
    enum {
        EVENT_PICPKER_STATE_CHANGE,
        EVENT_TYPE_MAX
    };

    using OnEventHandlerType = std::function<int32_t(AVCastPickerHelperInnerImpl*, std::shared_ptr<uintptr_t>&)>;
    using OffEventHandlerType = std::function<int32_t(AVCastPickerHelperInnerImpl*, std::shared_ptr<uintptr_t>&)>;

    int32_t AddCallback(int32_t event, std::shared_ptr<uintptr_t> &callback);
    int32_t RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> &callback);

    bool IsCallbacksEmpty(int32_t event);
    static int32_t NewInstance(uintptr_t context, AVCastPickerHelperInner &out);

    AVCastPickerHelperInnerImpl();
    explicit AVCastPickerHelperInnerImpl(OHOS::Ace::UIContent* uiContent);
    ~AVCastPickerHelperInnerImpl();

    void SelectSync(optional_view<AVCastPickerOptions> options);
    void OnPickerStateChange(callback_view<void(AVCastPickerState)> callback);
    void OffPickerStateChange(optional_view<callback<void(AVCastPickerState)>> callback);

private:
    static int32_t OnEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
        AVCastPickerHelperInnerImpl *taihePicker);
    static int32_t OffEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
        AVCastPickerHelperInnerImpl *taihePicker);

    static int32_t OnPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
        std::shared_ptr<uintptr_t> &callback);
    static int32_t OffPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
        std::shared_ptr<uintptr_t> &callback);

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;

    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;
    void HandleEvent(int32_t event, TaiheFuncExecute callback);
    void HandleEvent(int32_t event, uint32_t state);

    ani_env *env_ = nullptr;
    std::mutex lock_;
    std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    std::list<std::shared_ptr<uintptr_t>> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

    OHOS::Ace::UIContent *uiContent_;
    std::shared_ptr<uintptr_t> wrapperRef_{};

    static constexpr uint32_t STATE_APPEARING = 0;
    static constexpr uint32_t STATE_DISAPPEARING = 1;
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCAST_PICKER_HELPER_H
