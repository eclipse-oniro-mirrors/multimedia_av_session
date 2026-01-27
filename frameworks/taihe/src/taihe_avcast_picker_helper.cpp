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

namespace ANI::AVSession {

static const std::string ABILITY_WANT_PARAMS_UIEXTENSIONTARGETTYPE = "ability.want.params.uiExtensionType";
static const std::string ABILITY_WANT_ELEMENT_NAME = "com.ohos.mediacontroller";

std::map<std::string, std::pair<AVCastPickerHelperInnerImpl::OnEventHandlerType,
    AVCastPickerHelperInnerImpl::OffEventHandlerType>> AVCastPickerHelperInnerImpl::eventHandlers_ = {
    { "pickerStateChange", { OnPickerStateChangeInner, OffPickerStateChangeInner } },
};

AVCastPickerHelperInnerImpl::AVCastPickerHelperInnerImpl()
{
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
        SLOGE("AVCastPickerHelperInnerImpl NewInstance failed : uiContent is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "uiContent is nullptr");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    out = make_holder<AVCastPickerHelperInnerImpl, AVCastPickerHelperInner>(uiContent);
    SLOGD("AVCastPickerHelperInnerImpl NewInstance success");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVCastPickerHelperInnerImpl::AVCastPickerHelperInnerImpl(OHOS::Ace::UIContent* uiContent)
{
    SLOGI("construct");
    uiContent_ = uiContent;
    isValid_ = std::make_shared<bool>(true);
    audioRoutingMngr_ = OHOS::AudioStandard::AudioRoutingManager::GetInstance();
}

AVCastPickerHelperInnerImpl::~AVCastPickerHelperInnerImpl()
{
    SLOGI("destroy");
    if (isValid_) {
        *isValid_ = false;
    }
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
            "native uiContent_ is nullptr");
        return;
    }
    AVCastPickerHelperInnerImpl *taiheAVCastPickerHelper = this;
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallback = {
        .onRelease = ([callback](auto arg) { callback->OnRelease(arg); }),
        .onResult = ([callback](auto arg1, auto arg2) { callback->OnResult(arg1, arg2); }),
        .onReceive = ([callback, taiheAVCastPickerHelper](auto arg) {
            callback->OnReceive(arg);
            taiheAVCastPickerHelper->HandleEvent(EVENT_PICPKER_STATE_CHANGE, STATE_DISAPPEARING);
        }),
        .onError = ([callback](auto arg1, auto arg2, auto arg3) { callback->OnError(arg1, arg2, arg3); }),
        .onRemoteReady = ([callback, taiheAVCastPickerHelper](auto arg) {
            callback->OnRemoteReady(arg);
            taiheAVCastPickerHelper->HandleEvent(EVENT_PICPKER_STATE_CHANGE, STATE_APPEARING);
        }),
        .onDestroy = ([callback]() { callback->OnDestroy(); }),
    };
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent_->CreateModalUIExtension(request, extensionCallback, config);
    callback->SetSessionId(sessionId);
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
    if (stateTaihe == STATE_DISAPPEARING) {
        stateTaihe = AVCastPickerState::key_t::STATE_DISAPPEARING;
    } else if (stateTaihe == STATE_APPEARING) {
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

int32_t AVCastPickerHelperInnerImpl::AddCallback(int32_t event, std::shared_ptr<uintptr_t> &callback)
{
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

void ModalUICallback::OnRelease(int32_t releaseCode)
{
    SLOGI("ModalUICallback OnRelease enter. release code is %{public}d", releaseCode);
    CHECK_RETURN_VOID(uiContent_ != nullptr, "uiContent_ is nullptr");
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
    CHECK_RETURN_VOID(uiContent_ != nullptr, "uiContent_ is nullptr");
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
