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
#define LOG_TAG "TaiheAVCastControllerCallback"
#endif

#include "taihe_avcast_controller_callback.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_cast_control_command.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
TaiheAVCastControllerCallback::TaiheAVCastControllerCallback()
{
    SLOGI("Construct TaiheAVCastControllerCallback");
}

TaiheAVCastControllerCallback::~TaiheAVCastControllerCallback()
{
    SLOGI("Destroy TaiheAVCastControllerCallback");
}

void TaiheAVCastControllerCallback::ExecuteErrorCallback(std::shared_ptr<uintptr_t> method,
    int32_t errorCode, const std::string errorMsg) const
{
    std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
        std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(method);
    auto err = TaiheUtils::ToBusinessError(get_env(), errorCode, errorMsg);
    CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
    (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
}

void TaiheAVCastControllerCallback::HandleEvent(int32_t event, TaiheFuncExecute execute)
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

std::function<bool()> TaiheAVCastControllerCallback::CheckCallbackValid(int32_t event,
    const std::list<std::shared_ptr<uintptr_t>>::iterator &ref)
{
    return [this, event, ref]() {
        std::lock_guard<std::mutex> lockGuard(lock_);
        if (callbacks_[event].empty()) {
            SLOGE("checkCallbackValid with empty list for event %{public}d", event);
            return false;
        }
        bool hasFunc = false;
        for (auto it = callbacks_[event].begin(); it != callbacks_[event].end(); ++it) {
            hasFunc = (ref == it ? true : hasFunc);
        }
        SLOGD("checkCallbackValid return hasFunc %{public}d, %{public}d", hasFunc, event);
        return hasFunc;
    };
}

void TaiheAVCastControllerCallback::HandleErrorEvent(int32_t event, const int32_t errorCode,
    const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (callbacks_[event].empty()) {
        SLOGE("not register callback event=%{public}d", event);
        return;
    }
    CHECK_RETURN_VOID(asyncCallback_ != nullptr, "asyncCallback_ is nullptr");
    for (auto ref = callbacks_[event].begin(); ref != callbacks_[event].end(); ++ref) {
        asyncCallback_->CallWithFunc(*ref, isValid_, CheckCallbackValid(event, ref),
            [this, errorCode, errorMsg](std::shared_ptr<uintptr_t> method) {
                ExecuteErrorCallback(method, errorCode, errorMsg);
            });
    }
}

void TaiheAVCastControllerCallback::OnCastPlaybackStateChange(const OHOS::AVSession::AVPlaybackState &state)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnCastPlaybackStateChange");
    SLOGI("Start handle OnCastPlaybackStateChange event with state: %{public}d", state.GetState());
    auto execute = [state](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVPlaybackState stateTaihe = TaiheUtils::ToTaiheAVPlaybackState(state);
        std::shared_ptr<taihe::callback<void(AVPlaybackState const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVPlaybackState const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(stateTaihe);
    };
    HandleEvent(EVENT_CAST_PLAYBACK_STATE_CHANGE, execute);
}

void TaiheAVCastControllerCallback::OnMediaItemChange(const OHOS::AVSession::AVQueueItem &avQueueItem)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnMediaItemChange");
    SLOGI("Start handle OnMediaItemChange event");
    auto execute = [avQueueItem](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVQueueItem queueItemTaihe = TaiheUtils::ToTaiheAVQueueItem(avQueueItem);
        std::shared_ptr<taihe::callback<void(AVQueueItem const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVQueueItem const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(queueItemTaihe);
    };
    HandleEvent(EVENT_CAST_MEDIA_ITEM_CHANGE, execute);
}

void TaiheAVCastControllerCallback::OnPlayNext()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnPlayNext");
    SLOGI("Start handle OnPlayNext event");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_CAST_PLAY_NEXT, execute);
}

void TaiheAVCastControllerCallback::OnPlayPrevious()
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnPlayPrevious");
    SLOGI("Start handle OnPlayPrevious event");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_CAST_PLAY_PREVIOUS, execute);
}

void TaiheAVCastControllerCallback::OnSeekDone(const int32_t seekNumber)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnSeekDone");
    SLOGI("Start handle OnSeekDone event");
    auto execute = [seekNumber](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(seekNumber);
    };
    HandleEvent(EVENT_CAST_SEEK_DONE, execute);
}

void TaiheAVCastControllerCallback::OnVideoSizeChange(const int32_t width, const int32_t height)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnVideoSizeChange");
    SLOGI("Start handle OnVideoSizeChange event");
    auto execute = [width, height](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(int32_t, int32_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(int32_t, int32_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(width, height);
    };
    HandleEvent(EVENT_CAST_VIDEO_SIZE_CHANGE, execute);
}

void TaiheAVCastControllerCallback::HandlePlayerErrorAPI13(const int32_t errorCode, const std::string &errorMsg)
{
    CastExtErrCodeAPI13 TaiheErr;
    if (CAST_GENERIC_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Generic error
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_GENERIC_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else if (CAST_IO_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Input/Output errors
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_IO_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else if (CAST_PARSING_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Content parsing errors
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_PARSING_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else if (CAST_DECODE_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // Decoding errors
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_DECOD_EERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else if (CAST_RENDER_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // AudioRender errors
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_RENDER_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else if (CAST_DRM_ERRCODE_INFOS.count(static_cast<CastErrCode>(errorCode)) != 0 &&
        CASTERRCODE_TO_EXTERRORCODEAPI13.count(static_cast<CastErrCode>(errorCode)) != 0) {
        // DRM errors
        TaiheErr = CASTERRCODE_TO_EXTERRORCODEAPI13.at(static_cast<CastErrCode>(errorCode));
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_DRM_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else {
        SLOGW("Can not match error code, use default");
        // If error not in map, need add error and should not return default ERROR_CODE_UNSPECIFIED.
        TaiheErr = CAST_GENERICERR_EXT_API13_UNSPECIFIED;
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_GENERIC_ERR, static_cast<int32_t>(TaiheErr), errorMsg);
    }
}

void TaiheAVCastControllerCallback::OnPlayerError(const int32_t errorCode, const std::string &errorMsg)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnPlayerError");
    SLOGI("Start handle OnPlayerError event");
    if (static_cast<MediaServiceErrCode>(errorCode) >= MSERR_NO_MEMORY &&
        static_cast<MediaServiceErrCode>(errorCode) <= MSERR_EXTEND_START) {
        MediaServiceExtErrCodeAPI9 TaiheErr;
        if (MSERRCODE_INFOS.count(static_cast<MediaServiceErrCode>(errorCode)) != 0 &&
            MSERRCODE_TO_EXTERRORCODEAPI9.count(static_cast<MediaServiceErrCode>(errorCode)) != 0) {
            TaiheErr = MSERRCODE_TO_EXTERRORCODEAPI9.at(static_cast<MediaServiceErrCode>(errorCode));
        } else {
            SLOGW("Can not match error code, use default");
            // If error not in map, need add error and should not return default MSERR_EXT_API9_IO.
            TaiheErr = MSERR_EXT_API9_IO;
        }
        SLOGI("Native errCode: %{public}d, JS errCode: %{public}d", errorCode, static_cast<int32_t>(TaiheErr));
        HandleErrorEvent(EVENT_CAST_ERROR, static_cast<int32_t>(TaiheErr), errorMsg);
    } else {
        HandlePlayerErrorAPI13(errorCode, errorMsg);
    }
}

void TaiheAVCastControllerCallback::OnEndOfStream(const int32_t isLooping)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnEndOfStream");
    SLOGI("Start handle OnEndOfStream event");
    auto execute = [](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void()>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void()>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)();
    };
    HandleEvent(EVENT_CAST_END_OF_STREAM, execute);
}

void TaiheAVCastControllerCallback::OnPlayRequest(const OHOS::AVSession::AVQueueItem &avQueueItem)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnPlayRequest");
    SLOGI("Start handle OnPlayRequest event");
    auto execute = [avQueueItem](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        AVQueueItem queueItemTaihe = TaiheUtils::ToTaiheAVQueueItem(avQueueItem);
        std::shared_ptr<taihe::callback<void(AVQueueItem const&)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(AVQueueItem const&)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(queueItemTaihe);
    };
    HandleEvent(EVENT_CAST_PLAY_REQUEST, execute);
}

void TaiheAVCastControllerCallback::OnKeyRequest(const std::string &assetId,
    const std::vector<uint8_t> &keyRequestData)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnKeyRequest");
    SLOGI("Start handle OnKeyRequest event");
    dataContext_.keyRequestData = TaiheUtils::ToTaiheUint8Array(keyRequestData);
    dataContext_.assetId = string(assetId);
    array_view<uint8_t> dataTaihe = dataContext_.keyRequestData;
    string_view assetIdTaihe = dataContext_.assetId;
    auto execute = [assetIdTaihe, dataTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(string_view, array_view<uint8_t>)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(string_view, array_view<uint8_t>)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(assetIdTaihe, dataTaihe);
    };
    HandleEvent(EVENT_CAST_KEY_REQUEST, execute);
}

void TaiheAVCastControllerCallback::OnCastValidCommandChanged(const std::vector<int32_t> &cmds)
{
    SLOGI("Start handle OnValidCommandChanged event. cmd size:%{public}zd", cmds.size());
    std::vector<std::string> stringCmds = TaiheCastControlCommand::ConvertCommands(cmds);
    dataContext_.cmds = TaiheUtils::ToTaiheStringArray(stringCmds);
    array_view<string> cmdsTaihe = dataContext_.cmds;
    auto execute = [cmdsTaihe](std::shared_ptr<uintptr_t> method) {
        std::shared_ptr<taihe::callback<void(array_view<string>)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(array_view<string>)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(cmdsTaihe);
    };
    HandleEvent(EVENT_CAST_VALID_COMMAND_CHANGED, execute);
}

void TaiheAVCastControllerCallback::OnCustomData(const OHOS::AAFwk::WantParams &customData)
{
    OHOS::AVSession::AVSessionTrace trace("TaiheAVCastControllerCallback::OnCustomData");
    auto execute = [customData](std::shared_ptr<uintptr_t> method) {
        env_guard guard;
        CHECK_RETURN_VOID(guard.get_env() != nullptr, "guard env is nullptr");
        auto customDataAni = TaiheUtils::ToAniWantParams(customData);
        CHECK_RETURN_VOID(customDataAni != nullptr, "convert WantParams to ani object failed");
        uintptr_t customDataTaihe = reinterpret_cast<uintptr_t>(customDataAni);
        std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(method);
        CHECK_RETURN_VOID(cacheCallback != nullptr, "cacheCallback is nullptr");
        (*cacheCallback)(customDataTaihe);
    };
    HandleEvent(EVENT_CAST_CUSTOM_DATA_CHANGE, execute);
}

int32_t TaiheAVCastControllerCallback::onDataSrcRead(const std::shared_ptr<OHOS::AVSession::AVSharedMemoryBase>& mem,
    uint32_t length, int64_t pos, int32_t& result)
{
    SLOGI("taihe onDataSrcRead length %{public}d", length);
    return ReadDataSrc(mem, length, pos, result);
}

int32_t TaiheAVCastControllerCallback::ReadDataSrc(const std::shared_ptr<OHOS::AVSession::AVSharedMemoryBase>& mem,
    uint32_t length, int64_t pos, int32_t& result)
{
    result = 0;
    SLOGI("ReadDataSrc result %{public}d", result);
    return result;
}

int32_t TaiheAVCastControllerCallback::AddCallback(int32_t event, std::shared_ptr<uintptr_t> ref)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], ref, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb == nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been registered");
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);

    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<TaiheAsyncCallback>(get_env(), mainHandler_);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return OHOS::AVSession::ERR_NO_MEMORY;
        }
    }
    SLOGI("addCallback isValidSet to prevent off, with ref %{public}d", event);
    callbacks_[event].push_back(ref);
    if (isValid_ == nullptr) {
        SLOGI("addCallback with no isValid_ init");
        isValid_ = std::make_shared<bool>(true);
    } else {
        SLOGI("addCallback with isValid_ set true");
        *isValid_ = true;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheAVCastControllerCallback::RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    SLOGI("try remove callback for event %{public}d", event);
    if (callback == nullptr) {
        SLOGD("Remove callback, the callback is nullptr");
        for (auto callbackRef = callbacks_[event].begin(); callbackRef != callbacks_[event].end(); ++callbackRef) {
            *callbackRef = nullptr;
        }
        callbacks_[event].clear();
        // not remove this logic for play button will not valid when stopcast at media control second page
        SLOGE("RemoveCallback with isvalid set false when playbackstatechange off");
        if (event == EVENT_CAST_PLAYBACK_STATE_CHANGE) {
            if (isValid_ == nullptr) {
                SLOGE("remove callback with no isValid_ init");
                return OHOS::AVSession::AVSESSION_SUCCESS;
            }
            SLOGI("removeCallback with isValid_ set false");
            *isValid_ = false;
        }
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    std::shared_ptr<uintptr_t> targetCb;
    CHECK_AND_RETURN_RET_LOG(OHOS::AVSession::AVSESSION_SUCCESS == TaiheUtils::GetRefByCallback(
        callbacks_[event], callback, targetCb), OHOS::AVSession::AVSESSION_ERROR, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(targetCb != nullptr, OHOS::AVSession::AVSESSION_SUCCESS, "callback has been remove");
    callbacks_[event].remove(targetCb);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

bool TaiheAVCastControllerCallback::IsCallbacksEmpty(int32_t event)
{
    return callbacks_[event].empty();
}
} // namespace ANI::AVSession