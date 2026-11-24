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
#ifndef LOG_TAG
#define LOG_TAG "AVCastPickerHelperInnerImpl"
#endif

#include "ability.h"
#include "ability_context.h"
#include "ani_base_context.h"
#include "avsession_errors.h"
#include "avsession_trace.h"
#include "taihe_avsession_manager.h"
#include "taihe_avcast_picker_helper.h"
#include "taihe_utils.h"
#include "bool_wrapper.h"
#include "int_wrapper.h"

namespace ANI::AVSession {

static const std::string ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE = "ability.want.params.uiExtensionType";
static const std::string ABILITY_WANT_ELEMENT_NAME = "com.ohos.mediacontroller";

std::map<std::string, std::pair<AVCastPickerHelperInnerImpl::OnEventHandlerType,
    AVCastPickerHelperInnerImpl::OffEventHandlerType>> AVCastPickerHelperInnerImpl::eventHandlers_ = {
    { "pickerStateChange", { OnPickerStateChangeInner, OffPickerStateChangeInner } },
};

std::mutex AVCastPickerHelperInnerImpl::instanceLock_;
std::set<AVCastPickerHelperInnerImpl*> AVCastPickerHelperInnerImpl::instances_;

AVCastPickerHelperInnerImpl::AVCastPickerHelperInnerImpl()
{
    audioRoutingMngr_ = nullptr;
    SLOGI("AVCastPickerHelperInnerImpl construct");
}

int32_t AVCastPickerHelperInnerImpl::NewInstance(uintptr_t context, AVCastPickerHelperInner &out)
{
    ani_env *env = taihe::get_env();
    ani_object aniContext = reinterpret_cast<ani_object>(context);
    if (env == nullptr || aniContext == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "get stageContext failed");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    OHOS::Ace::UIContent* uiContent = nullptr;
    auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    if (stageContext == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "get stageContext failed");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(stageContext);
    if (abilityContext != nullptr) {
        uiContent = abilityContext->GetUIContent();
    } else {
        auto extensionContext =
           OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(stageContext);
        CHECK_RETURN(extensionContext != nullptr, "convert to AbilityContext and ExtensionContext fail",
            OHOS::AVSession::AVSESSION_ERROR);
        uiContent = extensionContext->GetUIContent();
    }
    if (!uiContent) {
        SLOGE("AVCastPickerHelperInnerImpl NewInstance failed : picker ui content is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "picker ui content is nullptr");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    out = make_holder<AVCastPickerHelperInnerImpl, AVCastPickerHelperInner>(uiContent);
    SLOGD("AVCastPickerHelperInnerImpl NewInstance success");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVCastPickerHelperInnerImpl::AVCastPickerHelperInnerImpl(OHOS::Ace::UIContent* uiContent)
{
    std::lock_guard<std::mutex> lockGuard(validLock_);
    SLOGI("construct");
    uiContent_ = uiContent;
    isValid_ = std::make_shared<std::atomic<bool>>(true);
    audioRoutingMngr_ = OHOS::AudioStandard::AudioRoutingManager::GetInstance();
    std::lock_guard<std::mutex> instanceLockGuard(instanceLock_);
    instances_.insert(this);
}

AVCastPickerHelperInnerImpl::~AVCastPickerHelperInnerImpl()
{
    std::lock_guard<std::mutex> lockGuard(validLock_);
    SLOGI("destroy");
    if (isValid_) {
        isValid_->store(false);
    }
    std::lock_guard<std::mutex> instanceLockGuard(instanceLock_);
    instances_.erase(this);
}

static int32_t GetTaiheAVCastPickerOptions(const AVCastPickerOptions &in, TaiheAVCastPickerOptions &out)
{
    if (in.sessionType.has_value()) {
        int32_t ret = TaiheUtils::GetString(in.sessionType.value(), out.sessionType);
        CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "get sessionType failed", ret);
    }
    if (in.pickerStyle.has_value()) {
        out.pickerStyle = in.pickerStyle.value().get_value();
    }
    if (in.menuPosition.has_value()) {
        int32_t ret = TaiheUtils::GetMenuPosition(in.menuPosition.value(), out.menuPosition);
        CHECK_RETURN(ret == OHOS::AVSession::AVSESSION_SUCCESS, "get menuPosition failed", ret);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

void AVCastPickerHelperInnerImpl::SelectSync(optional_view<AVCastPickerOptions> options)
{
    TaiheAVCastPickerOptions taiheAVCastPickerOptions;
    if (options.has_value()) {
        int32_t ret = GetTaiheAVCastPickerOptions(options.value(), taiheAVCastPickerOptions);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "SelectSync get options failed");
            return;
        }
    } else {
        SLOGI("TaiheAVCastPickerOptions use default options");
    }

    OHOS::AAFwk::Want request;
    std::string targetType = "sysPicker/mediaControl";
    request.SetParam(ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE, targetType);
    request.SetParam("isAVCastPickerHelper", true);
    request.SetParam("AVCastPickerOptionsType", taiheAVCastPickerOptions.sessionType);
    request.SetParam("AVCastPickerOptionsStyle", taiheAVCastPickerOptions.pickerStyle);
    request.SetParam("AVCastPickerOptionsPositionX", taiheAVCastPickerOptions.menuPosition.x);
    request.SetParam("AVCastPickerOptionsPositionY", taiheAVCastPickerOptions.menuPosition.y);
    request.SetParam("AVCastPickerOptionsPositionW", taiheAVCastPickerOptions.menuPosition.width);
    request.SetParam("AVCastPickerOptionsPositionH", taiheAVCastPickerOptions.menuPosition.height);
    request.SetElementName(ABILITY_WANT_ELEMENT_NAME, "UIExtAbility");

    PickerCallBack pickerCallBack;
    auto callback = std::make_shared<ModalUICallback>(uiContent_, pickerCallBack);
    if (callback == nullptr || uiContent_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "native picker ui content is nullptr");
        return;
    }
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallback = CreateExtensionCallback(callback, this);
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent_->CreateModalUIExtension(request, extensionCallback, config);
    callback->SetSessionId(sessionId);
}

int32_t AVCastPickerHelperInnerImpl::SelectForIdSync(optional_view<AVCastPickerOptions> options)
{
    TaiheAVCastPickerOptions taiheAVCastPickerOptions;
    if (options.has_value()) {
        int32_t ret = GetTaiheAVCastPickerOptions(options.value(), taiheAVCastPickerOptions);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "SelectForIdSync get options failed");
            return -1;
        }
    } else {
        SLOGI("TaiheAVCastPickerOptions use default options");
    }

    OHOS::AAFwk::Want request;
    std::string targetType = "sysPicker/mediaControl";
    request.SetParam(ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE, targetType);
    request.SetParam("isAVCastPickerHelper", true);
    request.SetParam("AVCastPickerOptionsType", taiheAVCastPickerOptions.sessionType);
    request.SetParam("AVCastPickerOptionsStyle", taiheAVCastPickerOptions.pickerStyle);
    request.SetParam("AVCastPickerOptionsPositionX", taiheAVCastPickerOptions.menuPosition.x);
    request.SetParam("AVCastPickerOptionsPositionY", taiheAVCastPickerOptions.menuPosition.y);
    request.SetParam("AVCastPickerOptionsPositionW", taiheAVCastPickerOptions.menuPosition.width);
    request.SetParam("AVCastPickerOptionsPositionH", taiheAVCastPickerOptions.menuPosition.height);
    request.SetElementName(ABILITY_WANT_ELEMENT_NAME, "UIExtAbility");

    PickerCallBack pickerCallBack;
    auto callback = std::make_shared<ModalUICallback>(uiContent_, pickerCallBack);
    if (callback == nullptr || uiContent_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "native picker ui content is nullptr");
        return -1;
    }
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallback = CreateExtensionCallback(callback, this);
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent_->CreateModalUIExtension(request, extensionCallback, config);
    callback->SetSessionId(sessionId);
    return sessionId;
}

void AVCastPickerHelperInnerImpl::CloseSync(optional_view<int32_t> pickerId)
{
    if (pickerId.has_value()) {
        int32_t ret = SendCloseData(pickerId.value());
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], "close failed");
        }
    } else {
        SendCloseDataToAll();
    }
}

OHOS::Ace::ModalUIExtensionCallbacks AVCastPickerHelperInnerImpl::CreateExtensionCallback(
    const std::shared_ptr<ModalUICallback>& callback, AVCastPickerHelperInnerImpl* taihePicker)
{
    return {
        .onRelease = ([callback, taihePicker](auto arg) {
            callback->OnRelease(arg);
            taihePicker->RemoveProxy(callback->GetSessionId());
        }),
        .onResult = ([callback](auto arg1, auto arg2) { callback->OnResult(arg1, arg2); }),
        .onReceive = ([callback, taihePicker](auto arg) {
            callback->OnReceive(arg);
            taihePicker->HandleEvent(EVENT_PICPKER_STATE_CHANGE, STATE_DISAPPEARING);
            taihePicker->HandleEventForId(EVENT_PICKER_STATE_CHANGE_FOR_ID,
                callback->GetSessionId(), STATE_DISAPPEARING);
        }),
        .onError = ([callback](auto arg1, auto arg2, auto arg3) { callback->OnError(arg1, arg2, arg3); }),
        .onRemoteReady = ([callback, taihePicker](auto arg) {
            callback->OnRemoteReady(arg);
            taihePicker->StoreProxy(callback->GetSessionId(), arg);
            taihePicker->HandleEvent(EVENT_PICPKER_STATE_CHANGE, STATE_APPEARING);
            taihePicker->HandleEventForId(EVENT_PICKER_STATE_CHANGE_FOR_ID,
                callback->GetSessionId(), STATE_APPEARING);
        }),
        .onDestroy = ([callback, taihePicker]() {
            callback->OnDestroy();
            taihePicker->RemoveProxy(callback->GetSessionId());
        }),
    };
}

void AVCastPickerHelperInnerImpl::StoreProxy(int32_t sessionId,
    const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& proxy)
{
    std::lock_guard<std::mutex> lockGuard(proxyLock_);
    proxyMap_[sessionId] = proxy;
    SLOGI("StoreProxy sessionId=%{public}d, map size=%{public}zu", sessionId, proxyMap_.size());
}

void AVCastPickerHelperInnerImpl::RemoveProxy(int32_t sessionId)
{
    std::lock_guard<std::mutex> lockGuard(proxyLock_);
    auto it = proxyMap_.find(sessionId);
    if (it != proxyMap_.end()) {
        proxyMap_.erase(it);
        SLOGI("RemoveProxy sessionId=%{public}d, map size=%{public}zu", sessionId, proxyMap_.size());
    }
}

int32_t AVCastPickerHelperInnerImpl::SendCloseData(int32_t pickerId)
{
    std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> proxy;
    {
        std::lock_guard<std::mutex> lockGuard(proxyLock_);
        auto it = proxyMap_.find(pickerId);
        if (it == proxyMap_.end() || it->second == nullptr) {
            SLOGE("SendCloseData proxy not found for pickerId=%{public}d", pickerId);
            return OHOS::AVSession::ERR_PICKER_NOT_EXIST;
        }
        proxy = it->second;
    }
    OHOS::AAFwk::WantParams params;
    params.SetParam("closeByPickerApi", OHOS::AAFwk::Boolean::Box(true));
    proxy->SendData(params);
    SLOGI("SendCloseData pickerId=%{public}d", pickerId);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

void AVCastPickerHelperInnerImpl::SendCloseDataToAll()
{
    std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>> proxies;
    {
        std::lock_guard<std::mutex> lockGuard(proxyLock_);
        for (auto& [id, proxy] : proxyMap_) {
            if (proxy != nullptr) {
                proxies.push_back(proxy);
            }
        }
    }
    SendCloseDataToProxies(proxies);
    SLOGI("SendCloseDataToAll count=%{public}zu", proxies.size());
}

std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>> AVCastPickerHelperInnerImpl::CollectAllProxies()
{
    std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>> allProxies;
    std::lock_guard<std::mutex> lockGuard(instanceLock_);
    for (auto* inst : instances_) {
        std::lock_guard<std::mutex> proxyLock(inst->proxyLock_);
        for (auto& [id, proxy] : inst->proxyMap_) {
            if (proxy != nullptr) {
                allProxies.push_back(proxy);
            }
        }
    }
    return allProxies;
}

void AVCastPickerHelperInnerImpl::SendCloseDataToProxies(
    const std::vector<std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>>& proxies)
{
    for (auto& proxy : proxies) {
        OHOS::AAFwk::WantParams params;
        params.SetParam("closeByPickerApi", OHOS::AAFwk::Boolean::Box(true));
        proxy->SendData(params);
    }
}

void AVCastPickerHelperInnerImpl::ResetCommunicationDeviceSync()
{
    OHOS::sptr<OHOS::AudioStandard::AudioRendererFilter> audioRendererFilter;
    AVCastPickerHelperInnerImpl *taiheAVCastPickerHelper = this;
    audioRendererFilter = new (std::nothrow) OHOS::AudioStandard::AudioRendererFilter();
    if (audioRendererFilter == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_MEMORY],
            "init AudioRendererFilter failed");
        return;
    }
    audioRendererFilter->rendererInfo.streamUsage = OHOS::AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION;
    CHECK_AND_RETURN_LOG(taiheAVCastPickerHelper != nullptr && taiheAVCastPickerHelper->audioRoutingMngr_ != nullptr,
        "get audioRoutingMngr null");
    taiheAVCastPickerHelper->audioRoutingMngr_->RestoreOutputDevice(audioRendererFilter);
    return;
}

void AVCastPickerHelperInnerImpl::OnPickerStateChange(callback_view<void(AVCastPickerState)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    OnEvent("pickerStateChange", cacheCallback, this);
}

void AVCastPickerHelperInnerImpl::OffPickerStateChange(optional_view<callback<void(AVCastPickerState)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    OffEvent("pickerStateChange", cacheCallback, this);
}

void AVCastPickerHelperInnerImpl::OnPickerStateChangeForId(
    callback_view<void(const AVCastPickerStateWithId&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    int32_t ret = AddCallback(EVENT_PICKER_STATE_CHANGE_FOR_ID, cacheCallback);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "add event callback failed");
    }
}

void AVCastPickerHelperInnerImpl::OffPickerStateChangeForId(
    optional_view<callback<void(const AVCastPickerStateWithId&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    int32_t ret = RemoveCallback(EVENT_PICKER_STATE_CHANGE_FOR_ID, cacheCallback);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "remove event callback failed");
    }
}

int32_t AVCastPickerHelperInnerImpl::OnEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
    AVCastPickerHelperInnerImpl *taihePicker)
{
    CHECK_AND_RETURN_RET_LOG(taihePicker != nullptr,
        TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM], "input param is nullptr");
    std::string eventName = event;
    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    auto* taiheAVCastPickerHelper = reinterpret_cast<AVCastPickerHelperInnerImpl*>(taihePicker);
    if (it->second.first(taiheAVCastPickerHelper, callback) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "add event callback failed");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVCastPickerHelperInnerImpl::OffEvent(const std::string& event, std::shared_ptr<uintptr_t> &callback,
    AVCastPickerHelperInnerImpl *taihePicker)
{
    std::string eventName = event;
    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    auto* taiheAVCastPickerHelper = reinterpret_cast<AVCastPickerHelperInnerImpl*>(taihePicker);
    if (taiheAVCastPickerHelper == nullptr) {
        SLOGE("OffEvent failed : taiheAVCastPickerHelper is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "OffEvent failed : taiheAVCastPickerHelper is nullptr");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    if (taiheAVCastPickerHelper != nullptr &&
        it->second.second(taiheAVCastPickerHelper, callback) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "remove event callback failed");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVCastPickerHelperInnerImpl::OnPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
    std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("AVCastPickerHelperInnerImpl OnPickerStateChange");
    CHECK_AND_RETURN_RET_LOG(taihePicker != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "input param is nullptr");
    return taihePicker->AddCallback(EVENT_PICPKER_STATE_CHANGE, callback);
}

int32_t AVCastPickerHelperInnerImpl::OffPickerStateChangeInner(AVCastPickerHelperInnerImpl *taihePicker,
    std::shared_ptr<uintptr_t> &callback)
{
    SLOGI("AVCastPickerHelperInnerImpl OffPickerStateChange");
    CHECK_AND_RETURN_RET_LOG(taihePicker != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "input param is nullptr");
    return taihePicker->RemoveCallback(EVENT_PICPKER_STATE_CHANGE, callback);
}

void AVCastPickerHelperInnerImpl::HandleEvent(int32_t event, uint32_t state)
{
    SLOGI("HandleEvent called with event: %{public}d, state: %{public}u", event, state);
    AVCastPickerState stateTaihe = AVCastPickerState::key_t::STATE_DISAPPEARING;
    if (state == STATE_DISAPPEARING) {
        stateTaihe = AVCastPickerState::key_t::STATE_DISAPPEARING;
    } else if (state == STATE_APPEARING) {
        stateTaihe = AVCastPickerState::key_t::STATE_APPEARING;
    } else {
        SLOGE("Invalid state: %{public}u", state);
        return;
    }
    auto execute = [stateTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(AVCastPickerState)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVCastPickerState)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe);
    };
    HandleEvent(EVENT_PICPKER_STATE_CHANGE, execute);
}

void AVCastPickerHelperInnerImpl::HandleEvent(int32_t event, TaiheFuncExecute execute)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    SLOGI("handle event for %{public}d", event);
    CHECK_RETURN_VOID(asyncCallback_ != nullptr, "asyncCallback_ is nullptr");

    for (auto callbackEntry = callbacks_[event].begin(); callbackEntry != callbacks_[event].end(); ++callbackEntry) {
        asyncCallback_->CallWithFunc(*callbackEntry, isValid_,
            [this, callbackEntry, event]() {
                std::lock_guard<std::mutex> lockGuard(lock_);
                if (callbacks_[event].empty()) {
                    SLOGE("checkCallbackValid with empty list for event %{public}d", event);
                    return false;
                }
                bool hasFunc = false;
                for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
                    hasFunc = (callbackEntry == it ? true : hasFunc);
                }
                SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
                return hasFunc;
            },
            execute);
    }
}

void AVCastPickerHelperInnerImpl::HandleEventForId(int32_t event, int32_t pickerId, uint32_t state)
{
    CHECK_RETURN_VOID(event == EVENT_PICKER_STATE_CHANGE_FOR_ID, "invalid event for HandleEventForId");
    SLOGI("HandleEventForId event=%{public}d pickerId=%{public}d, state=%{public}u", event, pickerId, state);
    AVCastPickerState stateTaihe = AVCastPickerState::key_t::STATE_DISAPPEARING;
    if (state == STATE_DISAPPEARING) {
        stateTaihe = AVCastPickerState::key_t::STATE_DISAPPEARING;
    } else if (state == STATE_APPEARING) {
        stateTaihe = AVCastPickerState::key_t::STATE_APPEARING;
    } else {
        SLOGE("Invalid state: %{public}u", state);
        return;
    }
    AVCastPickerStateWithId data {
        .id = pickerId,
        .state = stateTaihe,
    };
    auto execute = [data](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(AVCastPickerStateWithId)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVCastPickerStateWithId)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(data);
    };
    HandleEvent(event, execute);
}

int32_t AVCastPickerHelperInnerImpl::AddCallback(int32_t event, std::shared_ptr<uintptr_t> &callback)
{
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX,
        OHOS::AVSession::AVSESSION_ERROR, "no event:%{public}d", event);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr,
        OHOS::AVSession::AVSESSION_ERROR, "get callback null for event:%{public}d", event);
    SLOGI("Add callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb == nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been registered");
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);

    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<TaiheAsyncCallback>(env_, mainHandler_);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return OHOS::AVSession::ERR_NO_MEMORY;
        }
    }
    SLOGI("add callback with callback %{public}d", event);
    callbacks_[event].push_back(callback);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVCastPickerHelperInnerImpl::RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> &callback)
{
    CHECK_AND_RETURN_RET_LOG(event >= 0 && event < EVENT_TYPE_MAX,
        OHOS::AVSession::AVSESSION_ERROR, "no event:%{public}d", event);
    SLOGI("Remove callback %{public}d", event);
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callback == nullptr) {
        SLOGD("remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }

    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb != nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been remove");
    callbacks_[event].remove(targetCb);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

bool AVCastPickerHelperInnerImpl::IsCallbacksEmpty(int32_t event)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    return callbacks_[event].empty();
}

ModalUICallback::ModalUICallback(OHOS::Ace::UIContent *uiContent, PickerCallBack &pickerCallBack)
{
    this->uiContent_ = uiContent;
    this->pickerCallBack_ = pickerCallBack;
}

void ModalUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

int32_t ModalUICallback::GetSessionId() const
{
    return sessionId_;
}

void ModalUICallback::OnRelease(int32_t releaseCode)
{
    SLOGI("ModalUICallback OnRelease enter. release code is %{public}d", releaseCode);
    CHECK_RETURN_VOID(uiContent_ != nullptr, "picker ui content is nullptr");
    this->uiContent_->CloseModalUIExtension(this->sessionId_);
    pickerCallBack_.ready = true;
}

void ModalUICallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    SLOGI("ModalUICallback OnResult enter. resultCode code is %{public}d", resultCode);
    pickerCallBack_.resultCode = resultCode;
}

void ModalUICallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    SLOGI("ModalUICallback OnReceive enter.");
}

void ModalUICallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    SLOGI("ModalUICallback OnError enter. errorCode=%{public}d, name=%{public}s, message=%{public}s",
        code, name.c_str(), message.c_str());
    CHECK_RETURN_VOID(uiContent_ != nullptr, "picker ui content is nullptr");
    if (!pickerCallBack_.ready) {
        this->uiContent_->CloseModalUIExtension(this->sessionId_);
        pickerCallBack_.ready = true;
    }
}

void ModalUICallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    SLOGI("ModalUICallback OnRemoteReady enter.");
}

void ModalUICallback::OnDestroy()
{
    SLOGI("ModalUICallback OnDestroy enter.");
}

} // namespace OHOS::AVSession
