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
#define LOG_TAG "AVSessionImpl"
#endif

#include <cstdio>

#include "taihe_avsession.h"

#include "avsession_errors.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_trace.h"
#include "taihe_meta_data.h"
#include "taihe_playback_state.h"
#include "want_agent.h"
#include "want_params.h"
#include "taihe_avsession_controller.h"
#include "avsession_utils.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "taihe_avcast_controller.h"
#endif

namespace ANI::AVSession {
std::mutex AVSessionImpl::executeMutex_;
std::mutex AVSessionImpl::completeMutex_;
std::condition_variable AVSessionImpl::executeCond_;
std::condition_variable AVSessionImpl::completeCond_;
std::recursive_mutex registerEventLock_;
int32_t AVSessionImpl::playBackStateRet_ = OHOS::AVSession::AVSESSION_ERROR;
std::shared_ptr<AVSessionImpl> AVSessionImpl::taiheAVSession_ = nullptr;
std::list<int32_t> registerEventList_;
std::set<std::string> AVSessionImpl::onEventHandlers_ = {
    "play",
    "pause",
    "stop",
    "playNext",
    "playPrevious",
    "fastForward",
    "rewind",
    "seek",
    "setSpeed",
    "setLoopMode",
    "setTargetLoopMode",
    "toggleFavorite",
    "handleKeyEvent",
    "outputDeviceChange",
    "commonCommand",
    "skipToQueueItem",
    "answer",
    "hangUp",
    "toggleCallMute",
    "playFromAssetId",
    "playWithAssetId",
    "castDisplayChange",
    "customDataChange",
};
std::set<std::string> AVSessionImpl::offEventHandlers_ = {
    "play",
    "pause",
    "stop",
    "playNext",
    "playPrevious",
    "fastForward",
    "rewind",
    "seek",
    "setSpeed",
    "setLoopMode",
    "setTargetLoopMode",
    "toggleFavorite",
    "handleKeyEvent",
    "outputDeviceChange",
    "commonCommand",
    "skipToQueueItem",
    "answer",
    "hangUp",
    "toggleCallMute",
    "playFromAssetId",
    "playWithAssetId",
    "castDisplayChange",
    "customDataChange",
};
std::map<std::string, int32_t> convertEventType_ = {
    { "play", OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY },
    { "pause", OHOS::AVSession::AVControlCommand::SESSION_CMD_PAUSE },
    { "stop", OHOS::AVSession::AVControlCommand::SESSION_CMD_STOP },
    { "playNext", OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_NEXT },
    { "playPrevious", OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_PREVIOUS },
    { "fastForward", OHOS::AVSession::AVControlCommand::SESSION_CMD_FAST_FORWARD },
    { "rewind", OHOS::AVSession::AVControlCommand::SESSION_CMD_REWIND },
    { "seek", OHOS::AVSession::AVControlCommand::SESSION_CMD_SEEK },
    { "setSpeed", OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_SPEED },
    { "setLoopMode", OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_LOOP_MODE },
    { "toggleFavorite", OHOS::AVSession::AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE },
    { "handleKeyEvent", OHOS::AVSession::AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT },
    { "playFromAssetId", OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID },
    { "playWithAssetId", OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID }
};

int32_t AVSessionImpl::NewInstance(std::shared_ptr<OHOS::AVSession::AVSession> &nativeSession,
    struct AVSession &out, std::shared_ptr<AVSessionImpl> &taiheSession,
    const std::string &tag, OHOS::AppExecFwk::ElementName &elementName)
{
    taiheAVSession_ = std::make_shared<AVSessionImpl>(nativeSession, tag, elementName);
    CHECK_RETURN(taiheAVSession_ != nullptr, "make shared pointer failed", OHOS::AVSession::ERR_NO_MEMORY);

    out = make_holder<AVSessionImpl, struct AVSession>(taiheAVSession_);
    taiheSession = taiheAVSession_;
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVSessionImpl::ReCreateInstance(std::shared_ptr<OHOS::AVSession::AVSession> nativeSession)
{
    if (taiheAVSession_ == nullptr || nativeSession == nullptr) {
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    SLOGI("sessionId=%{public}s", taiheAVSession_->sessionId_.c_str());
    taiheAVSession_->sessionId_ = nativeSession->GetSessionId();
    taiheAVSession_->sessionType_ = nativeSession->GetSessionType();
    taiheAVSession_->session_ = std::move(nativeSession);
    if (taiheAVSession_->callback_ == nullptr) {
        taiheAVSession_->callback_ = std::make_shared<TaiheAVSessionCallback>(get_env());
    }
    if (taiheAVSession_->session_ == nullptr) {
        return OHOS::AVSession::AVSESSION_ERROR;
    }
    int32_t ret = taiheAVSession_->session_->RegisterCallback(taiheAVSession_->callback_);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("RegisterCallback fail, ret=%{public}d", ret);
    }

    {
        std::lock_guard lockGuard(registerEventLock_);
        for (int32_t event : registerEventList_) {
            int32_t res = taiheAVSession_->session_->AddSupportCommand(event);
            if (res != OHOS::AVSession::AVSESSION_SUCCESS) {
                SLOGE("AddSupportCommand fail, ret=%{public}d", res);
                continue;
            }
        }
    }

    taiheAVSession_->session_->Activate();
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVSessionImpl::AVSessionImpl()
{
    SLOGI("construct");
}

AVSessionImpl::AVSessionImpl(std::shared_ptr<OHOS::AVSession::AVSession> &nativeSession,
    const std::string &tag, OHOS::AppExecFwk::ElementName &elementName)
{
    CHECK_RETURN_VOID(nativeSession != nullptr, "nativeSession is nullptr");
    sessionId_ = nativeSession->GetSessionId();
    sessionType_ = nativeSession->GetSessionType();
    sessionTag_ = tag;
    elementName_ = elementName;
    session_ = std::move(nativeSession);
    SLOGI("sessionId=%{public}s, sessionType:%{public}s", sessionId_.c_str(), sessionType_.c_str());
}

AVSessionImpl::AVSessionImpl(std::shared_ptr<AVSessionImpl> &taiheSession)
{
    CHECK_RETURN_VOID(taiheSession != nullptr, "taiheSession is nullptr");
    sessionId_ = taiheSession->sessionId_;
    sessionType_ = taiheSession->sessionType_;
    sessionTag_ = taiheSession->sessionTag_;
    elementName_ = taiheSession->elementName_;
    session_ = taiheSession->session_;
}

AVSessionImpl::~AVSessionImpl()
{
    SLOGI("destroy");
    std::lock_guard lockGuard(registerEventLock_);
    registerEventList_.clear();
}

taihe::string AVSessionImpl::GetSessionId()
{
    return taihe::string(sessionId_);
}

taihe::string AVSessionImpl::GetSessionType()
{
    return taihe::string(sessionType_);
}

std::string AVSessionImpl::GetSessionIdInner()
{
    return sessionId_;
}

void AVSessionImpl::SetSessionIdInner(std::string sessionId)
{
    sessionId_ = sessionId;
}

std::string AVSessionImpl::GetSessionTypeInner()
{
    return sessionType_;
}

void AVSessionImpl::SetSessionTypeInner(std::string sessionType)
{
    sessionType_ = sessionType;
}

std::string AVSessionImpl::GetSessionTag()
{
    return sessionTag_;
}

void AVSessionImpl::SetSessionTag(std::string sessionTag)
{
    sessionTag_ = sessionTag;
}

OHOS::AppExecFwk::ElementName AVSessionImpl::GetSessionElement()
{
    return elementName_;
}

void AVSessionImpl::SetSessionElement(OHOS::AppExecFwk::ElementName elementName)
{
    elementName_ = elementName;
}

void ProcessErrMsg(int32_t ret)
{
    std::string errMessage = "SetAVMetaData failed : native server exception";
    if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
        errMessage = "SetAVMetaData failed : native session not exist";
    } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
        errMessage = "SetAVMetaData failed : native invalid parameters";
    } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
        errMessage = "SetAVMetaData failed : native no permission";
    }
    TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
}

int32_t DoDownload(OHOS::AVSession::AVMetaData &meta, const std::string &uri)
{
    SLOGI("DoDownload with title %{public}s",
        OHOS::AVSession::AVSessionUtils::GetAnonyTitle(meta.GetTitle()).c_str());

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = nullptr;
    bool ret = TaiheUtils::DoDownloadInCommon(pixelMap, uri);
    SLOGI("DoDownload with ret %{public}d, %{public}d", static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DoDownload success and reset meta except assetId but not, wait for mediacontrol fix");
        meta.SetMediaImage(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::AVSESSION_ERROR;
}

static bool DoMetaDataSetTaihe(std::shared_ptr<OHOS::AVSession::AVSession> &sessionPtr,
    OHOS::AVSession::AVMetaData &data, bool isRepeatDownload)
{
    std::string uri = data.GetMediaImageUri();
    SLOGI("do metadata set with check uri alive:%{public}d, pixel alive:%{public}d, session alive:%{public}d",
        static_cast<int>(!uri.empty()), static_cast<int>(data.GetMediaImage() != nullptr),
        static_cast<int>(sessionPtr != nullptr));
    if (sessionPtr == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetAVMetaData failed : session is nullptr");
        return false;
    }

    int32_t ret = sessionPtr->SetAVMetaData(data);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("do metadata set fail, ret:%{public}d", ret);
        ProcessErrMsg(ret);
    } else if (uri.empty()) {
        SLOGE("do metadata set with img uri empty");
    } else if (isRepeatDownload) {
        SLOGI("do metadata set with repeat uriSize:%{public}zu.", uri.size());
    } else if (data.GetMediaImage() == nullptr) {
        ret = DoDownload(data, uri);
        SLOGI("DoDownload uriSize:%{public}zu complete with ret %{public}d", uri.size(), ret);
        CHECK_AND_RETURN_RET_LOG(sessionPtr != nullptr, false, "doMetaDataSet without session");
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("DoDownload failed but not repeat setmetadata again");
        } else {
            return true;
        }
    }
    return false;
}

void AVSessionImpl::SetAVMetadataSync(AVMetadata const &data)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetAVMetadataSync");
    OHOS::AVSession::AVMetaData metaData;
    if (TaiheMetaData::GetAVMetaData(data, metaData) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetAVMetadataSync invalid av meta data");
        return;
    }

    if (metaData_.EqualWithUri(metaData)) {
        SLOGI("metadata is all same");
        return;
    }

    metaData_ = metaData;
    std::chrono::system_clock::time_point metadataTs;
    if (latestMetadataAssetId_ != metaData_.GetAssetId() || latestMetadataUri_ != metaData_.GetMediaImageUri() ||
        !metaData_.GetMediaImageUri().empty() || metaData_.GetMediaImage() != nullptr) {
        metadataTs = std::chrono::system_clock::now();
        latestMetadataUri_ = metaData_.GetMediaImageUri();
        latestMetadataAssetId_ = metaData_.GetAssetId();
        latestMetadataTs_ = metadataTs;
    }

    bool isRepeatDownload =
        (latestDownloadedAssetId_ == latestMetadataAssetId_) && (latestDownloadedUri_ == latestMetadataUri_);
    bool res = DoMetaDataSetTaihe(session_, metaData, isRepeatDownload);
    bool timeAvailable = metadataTs >= latestMetadataTs_;
    SLOGI("DoMetaDataSet res:%{public}d, time:%{public}d", static_cast<int>(res), static_cast<int>(timeAvailable));
    if (res && timeAvailable && session_ != nullptr) {
        latestDownloadedUri_ = metaData.GetMediaImageUri();
        latestDownloadedAssetId_ = metaData.GetAssetId();
        session_->SetAVMetaData(metaData);
    }
    metaData.Reset();
}

void AVSessionImpl::SetCallMetadataSync(CallMetadata const& data)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetCallMetadataSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetCallMetadataSync session failed : session is nullptr");
        return;
    }
    OHOS::AVSession::AVCallMetaData metaData;
    if (TaiheUtils::GetAVCallMetaData(data, metaData) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetCallMetadataSync get AVCallMetaData failed");
        return;
    }
    int32_t ret = session_->SetAVCallMetaData(metaData);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetCallMetadataSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetCallMetadataSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetCallMetadataSync failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetCallMetadataSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

std::function<void()> AVSessionImpl::PlaybackStateExecute(const std::shared_ptr<OHOS::AVSession::AVSession> &session,
    const OHOS::AVSession::AVPlaybackState &playBackState)
{
    return [session, playBackState]() {
        if (session == nullptr) {
            playBackStateRet_ = OHOS::AVSession::ERR_SESSION_NOT_EXIST;
            return;
        }
        playBackStateRet_ = session->SetAVPlaybackState(playBackState);
        executeCond_.notify_one();
        std::unique_lock<std::mutex> lock(completeMutex_);
        auto waitStatus = completeCond_.wait_for(lock, std::chrono::milliseconds(100));
        if (waitStatus == std::cv_status::timeout) {
            SLOGE("SetAVPlaybackStateSync in PlaybackStateExecute timeout");
            return;
        }
    };
}

std::function<void()> AVSessionImpl::PlaybackStateComplete()
{
    return []() {
        std::unique_lock<std::mutex> lock(executeMutex_);
        auto waitStatus = executeCond_.wait_for(lock, std::chrono::milliseconds(100));
        if (waitStatus == std::cv_status::timeout) {
            SLOGE("SetAVPlaybackStateSync in PlaybackStateComplete timeout");
            return;
        }

        if (playBackStateRet_ != OHOS::AVSession::AVSESSION_SUCCESS) {
            std::string errMessage = "SetAVPlaybackState failed : native server exception";
            if (playBackStateRet_ == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
                errMessage = "SetAVPlaybackState failed : native session not exist";
            } else if (playBackStateRet_ == OHOS::AVSession::ERR_INVALID_PARAM) {
                errMessage = "SetAVPlaybackState failed : native invalid parameters";
            } else if (playBackStateRet_ == OHOS::AVSession::ERR_NO_PERMISSION) {
                errMessage = "SetAVPlaybackState failed : native no permission";
            }
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[playBackStateRet_], errMessage);
        }
        completeCond_.notify_one();
    };
}

void AVSessionImpl::SetAVPlaybackStateSync(AVPlaybackState const &state)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetAVPlaybackStateSync");
    OHOS::AVSession::AVPlaybackState playBackState;
    if (TaihePlaybackState::GetAVPlaybackState(state, playBackState) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetAVPlaybackStateSync get playBackState failed");
        return;
    }

    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetAVPlaybackStateSync failed : session is nullptr");
        return;
    }

    auto executor = PlaybackStateExecute(session_, playBackState);
    CHECK_AND_PRINT_LOG(
        OHOS::AVSession::AVSessionEventHandler::GetInstance().AVSessionPostTask(executor, "SetAVPlaybackStateSync"),
        "AVSessionImpl SetAVPlaybackStateSync handler postTask failed");

    auto completer = PlaybackStateComplete();
    completer();
}

void AVSessionImpl::SetAVCallStateSync(AVCallState const& state)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetAVCallStateSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetAVCallStateSync session failed : session is nullptr");
        return;
    }
    OHOS::AVSession::AVCallState avCallState;
    if (TaiheUtils::GetAVCallState(state, avCallState) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetAVCallStateSync get AVCallState failed");
        return;
    }
    int32_t ret = session_->SetAVCallState(avCallState);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetAVCallStateSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetAVCallStateSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetAVCallStateSync failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetAVCallStateSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::SetLaunchAbilitySync(uintptr_t ability)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetLaunchAbilitySync");
    OHOS::AbilityRuntime::WantAgent::WantAgent* wantAgent;
    if (TaiheUtils::GetWantAgent(ability, wantAgent) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetLaunchAbilitySync get wantAgent failed");
        return;
    }

    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetLaunchAbilitySync failed : session is nullptr");
        return;
    }
    if (wantAgent == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetLaunchAbilitySync failed : wantAgent is nullptr");
        return;
    }
    int32_t ret = session_->SetLaunchAbility(*wantAgent);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetLaunchAbility failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetLaunchAbility failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetLaunchAbility failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::DispatchSessionEventSync(string_view event, uintptr_t args)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::DispatchSessionEventSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "DispatchSessionEventSync session failed : session is nullptr");
        return;
    }
    std::string eventStr;
    if (TaiheUtils::GetString(event, eventStr) != OHOS::AVSession::AVSESSION_SUCCESS || eventStr.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "DispatchSessionEventSync failed : invalid event");
        return;
    }
    OHOS::AAFwk::WantParams wantParams;
    if (TaiheUtils::GetWantParams(args, wantParams) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "DispatchSessionEventSync failed : invalid wantParams args");
        return;
    }
    int32_t ret = session_->SetSessionEvent(eventStr, wantParams);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage;
        ErrCodeToMessage(ret, errMessage);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::SetAVQueueItemsSync(array_view<AVQueueItem> items)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetAVQueueItemsSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetAVQueueItemsSync session failed : session is nullptr");
        return;
    }
    std::vector<OHOS::AVSession::AVQueueItem> itemArray;
    if (TaiheUtils::GetAVQueueItemArray(items, itemArray) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetAVQueueItemsSync get AVQueueItemArray failed");
        return;
    }
    for (auto &item : itemArray) {
        if (!item.IsValid()) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
                "SetAVQueueItemsSync failed : invalid queue item content");
            return;
        }
    }
    int32_t ret = session_->SetAVQueueItems(itemArray);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetAVQueueItemsSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetAVQueueItemsSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetAVQueueItemsSync failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetAVQueueItemsSync failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_MARSHALLING) {
            errMessage = "SetAVQueueItemsSync failed : item number is out of range";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::SetAVQueueTitleSync(string_view title)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetAVQueueTitleSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetAVQueueTitleSync session failed : session is nullptr");
        return;
    }
    std::string titleStr;
    if (TaiheUtils::GetString(title, titleStr) != OHOS::AVSession::AVSESSION_SUCCESS || titleStr.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetAVQueueTitleSync failed : invalid title");
        return;
    }
    int32_t ret = session_->SetAVQueueTitle(titleStr);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetAVQueueTitleSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetAVQueueTitleSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetAVQueueTitleSync failed : native invalid parameters";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetAVQueueTitleSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::SetExtrasSync(uintptr_t extras)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SetExtrasSync");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SetExtrasSync session failed : session is nullptr");
        return;
    }
    OHOS::AAFwk::WantParams nativeExtras;
    if (TaiheUtils::GetWantParams(extras, nativeExtras) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetExtrasSync get extras failed");
        return;
    }
    int32_t ret = session_->SetExtras(nativeExtras);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetExtrasSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetExtrasSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_INVALID_PARAM) {
            errMessage = "SetExtrasSync failed : native invalid parameters";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

AVSessionController AVSessionImpl::GetControllerSync()
{
    SLOGI("AVSessionImpl::GetControllerSync enter");
    AVSessionController undefinedController = make_holder<AVSessionControllerImpl, AVSessionController>();
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "GetControllerSync failed : session is nullptr");
        return undefinedController;
    }

    std::shared_ptr<OHOS::AVSession::AVSessionController> controller = session_->GetController();
    if (controller == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetControllerSync failed : native get controller failed");
        return undefinedController;
    }

    AVSessionController output = make_holder<AVSessionControllerImpl, AVSessionController>();
    int32_t retInstance = AVSessionControllerImpl::NewInstance(controller, output);
    if (retInstance != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedController;
    }
    return output;
}

optional<AVCastController> AVSessionImpl::GetAVCastControllerSync()
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::GetAVCastControllerSync");
    optional<AVCastController> undefinedCastController = optional<AVCastController>(std::nullopt);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "GetAVCastControllerSync failed : session is nullptr");
        return undefinedCastController;
    }

    std::shared_ptr<OHOS::AVSession::AVCastController> castController = session_->GetAVCastController();
    if (castController == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetAVCastControllerSync failed : native get controller failed");
        return undefinedCastController;
    }

    AVCastController output = make_holder<AVCastControllerImpl, AVCastController>();
    int32_t retInstance = AVCastControllerImpl::NewInstance(castController, output);
    if (retInstance != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedCastController;
    }
    return optional<AVCastController>(std::in_place, output);
#else
    return undefinedCastController;
#endif
}

OutputDeviceInfo AVSessionImpl::GetOutputDeviceSync()
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::GetOutputDeviceSync");
    OutputDeviceInfo undefinedOutput = TaiheUtils::CreateUndefinedOutputDeviceInfo();
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "GetOutputDeviceSync failed : session is nullptr");
        return undefinedOutput;
    }

    OHOS::AVSession::AVSessionDescriptor descriptor;
    int ret = OHOS::AVSession::AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(
        session_->GetSessionId(), descriptor);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetOutputDeviceSync failed : native get av session descriptor failed");
        return undefinedOutput;
    }
    return TaiheUtils::ToTaiheOutputDeviceInfo(descriptor.outputDeviceInfo_);
}

array<CastDisplayInfo> AVSessionImpl::GetAllCastDisplaysSync()
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::GetAllCastDisplaysSync");
    std::vector<CastDisplayInfo> emptyInfoVec;
    array<CastDisplayInfo> undefinedInfo(emptyInfoVec);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "GetAllCastDisplaysSync failed : session is nullptr");
        return undefinedInfo;
    }

    std::vector<OHOS::AVSession::CastDisplayInfo> castDisplays;
    int32_t ret = session_->GetAllCastDisplays(castDisplays);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAllCastDisplays failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAllCastDisplays failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAllCastDisplays failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedInfo;
    }
    return TaiheUtils::ToTaiheCastDisplayInfoArray(castDisplays);
#else
    return undefinedInfo;
#endif
}

void AVSessionImpl::StopCastingSync()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "StopCastingSync failed : session is nullptr");
        return;
    }

    int32_t ret = session_->ReleaseCast();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "ReleaseCast failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "ReleaseCast failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "ReleaseCast failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
#endif
}

void AVSessionImpl::ActivateSync()
{
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "Activate session failed : session is nullptr");
        return;
    }

    int32_t ret = session_->Activate();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "Activate session failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "Activate session failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "Activate session failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::DeactivateSync()
{
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "Deactivate session failed : session is nullptr");
        return;
    }

    int32_t ret = session_->Deactivate();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "Deactivate session failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "Deactivate session failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "Deactivate session failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionImpl::DestroySync()
{
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "Destroy session failed : session is nullptr");
        return;
    }

    int32_t ret = session_->Destroy();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "Destroy session failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "Destroy session failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "Destroy session failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    } else {
        session_ = nullptr;
        callback_ = nullptr;
        return;
    }
}

void AVSessionImpl::SendCustomDataSync(uintptr_t data)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionImpl::SendCustomData");
    if (session_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "SendCustomDataSync failed : session is nullptr");
        return;
    }
    OHOS::AAFwk::WantParams dataArgs;
    if (TaiheUtils::GetWantParams(data, dataArgs) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendCustomDataSync failed : invalid command args");
        return;
    }
    int32_t ret = session_->SendCustomData(dataArgs);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendCustomData failed : native server exception, \
            you are advised to : 1.scheduled retry.\
            2.destroy the current session or session controller and re-create it.";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SendCustomDataSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SendCustomDataSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendCustomDataSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AddRegisterEvent(std::string eventName)
{
    std::lock_guard lockGuard(registerEventLock_);
    registerEventList_.push_back(convertEventType_[eventName]);
}

void RemoveRegisterEvent(std::string eventName)
{
    std::lock_guard lockGuard(registerEventLock_);
    registerEventList_.remove(convertEventType_[eventName]);
}

void AVSessionImpl::OnPlay(callback_view<void(CommandInfo const& commandInfo)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "play";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PLAY, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnPause(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "pause";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PAUSE);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PAUSE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnStop(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "stop";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_STOP);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_STOP, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnPlayNext(callback_view<void(CommandInfo const& commandInfo)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "playNext";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_NEXT);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PLAY_NEXT, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnPlayPrevious(callback_view<void(CommandInfo const& commandInfo)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "playPrevious";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PLAY_PREVIOUS, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnFastForward(callback_view<void(int64_t time, CommandInfo const& commandInfo)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "fastForward";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_FAST_FORWARD);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_FAST_FORWARD, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnRewind(callback_view<void(int64_t time, CommandInfo const& commandInfo)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "rewind";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_REWIND);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_REWIND, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnPlayFromAssetId(callback_view<void(int64_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "playFromAssetId";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PLAY_FROM_ASSETID, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnPlayWithAssetId(callback_view<void(string_view)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "playWithAssetId";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_PLAY_WITH_ASSETID, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnSeek(callback_view<void(int64_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "seek";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SEEK);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SEEK, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnSetSpeed(callback_view<void(double)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "setSpeed";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_SPEED);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SET_SPEED, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnSetLoopMode(callback_view<void(LoopMode)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "setLoopMode";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SET_LOOP_MODE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnSetTargetLoopMode(callback_view<void(LoopMode)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "setTargetLoopMode";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status =
            session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SET_TARGET_LOOP_MODE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnToggleFavorite(callback_view<void(string_view)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "toggleFavorite";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_TOGGLE_FAVORITE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnHandleKeyEvent(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "handleKeyEvent";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_MEDIA_KEY_EVENT, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnOutputDeviceChange(callback_view<void(ConnectionState, OutputDeviceInfo const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "outputDeviceChange";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnCommonCommand(callback_view<void(string_view, uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "commonCommand";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SEND_COMMON_COMMAND, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnSkipToQueueItem(callback_view<void(int32_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "skipToQueueItem";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnAnswer(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "answer";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_ANSWER);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_AVCALL_ANSWER, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnHangUp(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "hangUp";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_HANG_UP);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_AVCALL_HANG_UP, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnToggleCallMute(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "toggleCallMute";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "session_ is nullptr");
        int32_t status = session_->AddSupportCommand(
            OHOS::AVSession::AVControlCommand::SESSION_CMD_AVCALL_TOGGLE_CALL_MUTE);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add command failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_AVCALL_TOGGLE_CALL_MUTE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        AddRegisterEvent(eventName);
    }
}

void AVSessionImpl::OnCastDisplayChange(callback_view<void(CastDisplayInfo const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    const std::string eventName = "castDisplayChange";
    if (OnEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_DISPLAY_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
        session_->StartCastDisplayListener();
        AddRegisterEvent(eventName);
#endif
    }
}

void AVSessionImpl::OnCustomDataChange(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("customDataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t status = callback_->AddCallback(TaiheAVSessionCallback::EVENT_CUSTOM_DATA_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "add callback failed");
    }
}

void AVSessionImpl::OffPlay(optional_view<callback<void(CommandInfo const& commandInfo)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "play";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PLAY, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PLAY)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffPause(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "pause";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PAUSE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PAUSE)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PAUSE);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffStop(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "stop";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_STOP, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_STOP)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_STOP);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffPlayNext(optional_view<callback<void(CommandInfo const& commandInfo)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "playNext";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PLAY_NEXT, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PLAY_NEXT)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_NEXT);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffPlayPrevious(optional_view<callback<void(CommandInfo const& commandInfo)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "playPrevious";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PLAY_PREVIOUS, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PLAY_PREVIOUS)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffFastForward(optional_view<callback<void(int64_t time, CommandInfo const& commandInfo)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "fastForward";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_FAST_FORWARD, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_FAST_FORWARD)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_FAST_FORWARD);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffRewind(optional_view<callback<void(int64_t time, CommandInfo const& commandInfo)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "rewind";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_REWIND, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_REWIND)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_REWIND);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffPlayFromAssetId(optional_view<callback<void(int64_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "playFromAssetId";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PLAY_FROM_ASSETID, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PLAY_FROM_ASSETID)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(
                OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_FROM_ASSETID);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffPlayWithAssetId(optional_view<callback<void(string_view)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "playWithAssetId";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_PLAY_WITH_ASSETID, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_PLAY_WITH_ASSETID)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(
                OHOS::AVSession::AVControlCommand::SESSION_CMD_PLAY_WITH_ASSETID);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffSeek(optional_view<callback<void(int64_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "seek";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SEEK, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_SEEK)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SEEK);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffSetSpeed(optional_view<callback<void(double)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "setSpeed";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SET_SPEED, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_SET_SPEED)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_SPEED);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffSetLoopMode(optional_view<callback<void(LoopMode)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "setLoopMode";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SET_LOOP_MODE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_SET_LOOP_MODE)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffSetTargetLoopMode(optional_view<callback<void(LoopMode)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "setTargetLoopMode";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SET_TARGET_LOOP_MODE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_SET_TARGET_LOOP_MODE)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret =
                session_->DeleteSupportCommand(OHOS::AVSession::AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffToggleFavorite(optional_view<callback<void(string_view)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "toggleFavorite";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_TOGGLE_FAVORITE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_TOGGLE_FAVORITE)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(
                OHOS::AVSession::AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffHandleKeyEvent(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "handleKeyEvent";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_MEDIA_KEY_EVENT, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        if (callback_ && callback_->IsCallbacksEmpty(TaiheAVSessionCallback::EVENT_MEDIA_KEY_EVENT)) {
            CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
            int32_t ret = session_->DeleteSupportCommand(
                OHOS::AVSession::AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT);
            CHECK_RETURN_VOID_THROW_OFF_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "delete cmd failed");
        }
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffOutputDeviceChange(
    optional_view<callback<void(ConnectionState, OutputDeviceInfo const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "outputDeviceChange";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_OUTPUT_DEVICE_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffCommonCommand(optional_view<callback<void(string_view, uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "commonCommand";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SEND_COMMON_COMMAND, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffSkipToQueueItem(optional_view<callback<void(int32_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "skipToQueueItem";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_SKIP_TO_QUEUE_ITEM, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffAnswer(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "answer";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_AVCALL_ANSWER, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffHangUp(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "hangUp";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_AVCALL_HANG_UP, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffToggleCallMute(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "toggleCallMute";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_AVCALL_TOGGLE_CALL_MUTE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
        RemoveRegisterEvent(eventName);
    }
}

void AVSessionImpl::OffCastDisplayChange(optional_view<callback<void(CastDisplayInfo const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    const std::string eventName = "castDisplayChange";
    if (OffEvent(eventName, this) == OHOS::AVSession::AVSESSION_SUCCESS) {
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "TaiheAVSessionCallback object is nullptr");
        auto status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_DISPLAY_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
        CHECK_RETURN_VOID_THROW_OFF_ERR(session_ != nullptr, "TaiheAVSession object is nullptr");
        session_->StopCastDisplayListener();
        RemoveRegisterEvent(eventName);
#endif
    }
}

void AVSessionImpl::OffCustomDataChange(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("customDataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_OFF_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t status = callback_->RemoveCallback(TaiheAVSessionCallback::EVENT_CUSTOM_DATA_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_OFF_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "remove callback failed");
    }
}

int32_t AVSessionImpl::OnEvent(const std::string& event, AVSessionImpl *taiheSession)
{
    CHECK_AND_RETURN_RET_LOG(taiheSession != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheSession is nullptr");
    std::string eventName = event;
    auto it = onEventHandlers_.find(eventName);
    if (it == onEventHandlers_.end()) {
        SLOGE("event name invalid");
        ThrowErrorAndReturn("event name invalid", OHOS::AVSession::ERR_INVALID_PARAM);
    }
    if (taiheSession->session_ == nullptr) {
        SLOGE("OnEvent failed : session is nullptr");
        return ThrowErrorAndReturn("OnEvent failed : session is nullptr", OHOS::AVSession::ERR_SESSION_NOT_EXIST);
    }
    if (taiheSession->callback_ == nullptr) {
        taiheSession->callback_ = std::make_shared<TaiheAVSessionCallback>(get_env());
        if (taiheSession->callback_ == nullptr) {
            return ThrowErrorAndReturn("OnEvent failed : no memory", OHOS::AVSession::ERR_NO_MEMORY);
        }
        int32_t ret = taiheSession->session_->RegisterCallback(taiheSession->callback_);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            return ThrowErrorAndReturnByErrCode("OnEvent", ret);
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVSessionImpl::OffEvent(const std::string& event, AVSessionImpl *taiheSession)
{
    std::string eventName = event;
    auto it = offEventHandlers_.find(eventName);
    if (it == offEventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    if (taiheSession == nullptr) {
        SLOGE("OffEvent failed : taiheSession is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "OffEvent failed : taiheSession is nullptr");
        return OHOS::AVSession::ERR_SESSION_NOT_EXIST;
    }
    if (taiheSession->session_ == nullptr) {
        SLOGE("OffEvent failed : session is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_SESSION_NOT_EXIST],
            "OffEvent failed : session is nullptr");
        return OHOS::AVSession::ERR_SESSION_NOT_EXIST;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

void AVSessionImpl::ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case OHOS::AVSession::ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case OHOS::AVSession::ERR_INVALID_PARAM:
            message = "SetSessionEvent failed : native invalid parameters";
            break;
        case OHOS::AVSession::ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

int32_t AVSessionImpl::ThrowErrorAndReturn(const std::string& message, int32_t errCode)
{
    std::string tempMessage = message;
    TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[errCode], tempMessage.c_str());
    return errCode;
}

int32_t AVSessionImpl::ThrowErrorAndReturnByErrCode(const std::string& message, int32_t errCode)
{
    std::string tempMessage = message;
    if (errCode == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
        tempMessage.append(" failed : native session not exist");
    } else if (errCode == OHOS::AVSession::ERR_INVALID_PARAM) {
        tempMessage.append(" failed : native invalid parameters");
    } else if (errCode == OHOS::AVSession::ERR_NO_PERMISSION) {
        tempMessage.append(" failed : native no permission");
    } else {
        tempMessage.append(" failed : native server exception");
    }
    SLOGI("throw error message: %{public}s", tempMessage.c_str());
    TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[errCode], tempMessage.c_str());
    return errCode;
}
} // namespace ANI::AVSession