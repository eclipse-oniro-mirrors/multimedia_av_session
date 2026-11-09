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

#include <atomic>
#include <map>
#include <set>

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

struct TaiheMenuPosition {
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
};

class ModalUICallback {
public:
    explicit ModalUICallback(OHOS::Ace::UIContent* uiContent, PickerCallBack& pickerCallBack);
    void SetSessionId(int32_t sessionId);
    int32_t GetSessionId() const;
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();

private:
    int32_t sessionId_ = -1;
    OHOS::Ace::UIContent* uiContent_;
    PickerCallBack pickerCallBack_;
};

struct TaiheAVCastPickerOptions {
    std::string sessionType = "audio";
    int32_t pickerStyle = 0;
    TaiheMenuPosition menuPosition;
};

class AVCastPickerHelperInnerImpl {
public:
    enum {
        EVENT_PICPKER_STATE_CHANGE,
        EVENT_PICKER_STATE_CHANGE_FOR_ID,
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
    int32_t SelectForIdSync(optional_view<AVCastPickerOptions> options);
    void CloseSync(optional_view<int32_t> pickerId);
    void ResetCommunicationDeviceSync();
    void OnPickerStateChange(callback_view<void(AVCastPickerState)> callback);
    void OffPickerStateChange(optional_view<callback<void(AVCastPickerState)>> callback);
    void OnPickerStateChangeForId(callback_view<void(const AVCastPickerStateWithId&)> callback);
    void OffPickerStateChangeForId(optional_view<callback<void(const AVCastPickerStateWithId&)>> callback);

    static std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>> CollectAllProxies();
    static void SendCloseDataToProxies(const std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>>& proxies);

private:
    static int32_t OnEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
        AVCastPickerHelperInnerImpl *taihePicker);
    static int32_t OffEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
        AVCastPickerHelperInnerImpl *taihePicker);

    static int32_t OnPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
        std::shared_ptr<uintptr_t> &callback);
    static int32_t OffPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
        std::shared_ptr<uintptr_t> &callback);

    static OHOS::Ace::ModalUIExtensionCallbacks CreateExtensionCallback(
        const std::shared_ptr<ModalUICallback>& callback, AVCastPickerHelperInnerImpl* taihePicker);

    void StoreProxy(int32_t sessionId, const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& proxy);
    void RemoveProxy(int32_t sessionId);
    int32_t SendCloseData(int32_t pickerId);
    void SendCloseDataToAll();

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> eventHandlers_;
    static std::mutex instanceLock_;
    static std::set<AVCastPickerHelperInnerImpl*> instances_;

    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;
    void HandleEvent(int32_t event, TaiheFuncExecute callback);
    void HandleEvent(int32_t event, uint32_t state);
    void HandleEventForId(int32_t event, int32_t pickerId, uint32_t state);

    ani_env *env_ = nullptr;
    std::mutex lock_;
    std::mutex validLock_;
    std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    std::list<std::shared_ptr<uintptr_t>> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<std::atomic<bool>> isValid_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

    std::mutex proxyLock_;
    std::map<int32_t, std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>> proxyMap_;

    OHOS::Ace::UIContent *uiContent_;
    std::shared_ptr<uintptr_t> wrapperRef_{};

    OHOS::AudioStandard::AudioRoutingManager *audioRoutingMngr_;

    static constexpr uint32_t STATE_APPEARING = 0;
    static constexpr uint32_t STATE_DISAPPEARING = 1;
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCAST_PICKER_HELPER_H
