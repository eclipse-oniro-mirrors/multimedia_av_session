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

#include "OHAVSession.h"
#include "avmeta_data.h"
#include "avsession_manager.h"

namespace OHOS::AVSession {
OHAVSession::~OHAVSession()
{
}

OHAVSession::OHAVSession()
{
}

OHAVSession::OHAVSession(AVSession_Type sessionType, const char* sessionTag,
    const char* bundleName, const char* abilityName)
{
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    avSession_ = AVSessionManager::GetInstance().CreateSession(sessionTag, sessionType, elementName);
}

bool OHAVSession::IsAVSessionNull()
{
    return avSession_ == nullptr;
}

AVSession_ErrCode OHAVSession::GetEncodeErrcode(int32_t ret)
{
    auto it = errcodes.find(ret);
    if (it != errcodes.end()) {
        return it->second;
    }
    return AV_SESSION_ERR_SERVICE_EXCEPTION;
}

AVSession_ErrCode OHAVSession::Activate()
{
    int32_t ret = avSession_->Activate();
    return GetEncodeErrcode(ret);
}


AVSession_ErrCode OHAVSession::Deactivate()
{
    int32_t ret = avSession_->Deactivate();
    return GetEncodeErrcode(ret);
}

std::string OHAVSession::GetSessionType()
{
    std::string sessionType = avSession_->GetSessionType();
    return sessionType;
}

std::string OHAVSession::GetSessionId()
{
    std::string session_id = avSession_->GetSessionId();
    return session_id;
}

__attribute__((no_sanitize("cfi"))) AVSession_ErrCode OHAVSession::SetAVMetaData(OH_AVMetadata *metadata)
{
    AVMetaData* avMetaData = reinterpret_cast<AVMetaData*>(metadata);
    int32_t ret = avSession_->SetAVMetaData(*avMetaData);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVSession::SetPlaybackState(AVSession_PlaybackState playbackState)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetState(playbackState);
    int32_t ret = avSession_->SetAVPlaybackState(avPlaybackState);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVSession::SetPlaybackPosition(AVSession_PlaybackPosition* playbackPosition)
{
    AVPlaybackState avPlaybackState;
    AVPlaybackState::Position pos = {playbackPosition->elapsedTime, playbackPosition->updateTime};
    avPlaybackState.SetPosition(pos);
    int32_t ret = avSession_->SetAVPlaybackState(avPlaybackState);
    return GetEncodeErrcode(ret);
}

__attribute__((no_sanitize("cfi"))) AVSession_ErrCode OHAVSession::SetFavorite(bool favorite)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetFavorite(favorite);
    int32_t ret = avSession_->SetAVPlaybackState(avPlaybackState);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVSession::SetLoopMode(AVSession_LoopMode loopMode)
{
    AVPlaybackState avPlaybackState;
    avPlaybackState.SetLoopMode(loopMode);
    int32_t ret = avSession_->SetAVPlaybackState(avPlaybackState);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVSession::RegisterCommandCallback(AVSession_ControlCommand command,
    OH_AVSessionCallback_OnCommand callback, void* userData)
{
    int32_t ret = 0;
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (ohAVSessionCallbackImpl_ == nullptr) {
        ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
        ret = avSession_->RegisterCallback(ohAVSessionCallbackImpl_);
    }
    ret = avSession_->AddSupportCommand(static_cast<int32_t>(command));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    switch (command) {
        case CONTROL_CMD_PLAY:
            ohAVSessionCallbackImpl_->SetPlayCallback((OH_AVSession*)this, command, callback, userData);
            break;
        case CONTROL_CMD_PAUSE:
            ohAVSessionCallbackImpl_->SetPauseCallback((OH_AVSession*)this, command, callback, userData);
            break;
        case CONTROL_CMD_STOP:
            ohAVSessionCallbackImpl_->SetStopCallback((OH_AVSession*)this, command, callback, userData);
            break;
        case CONTROL_CMD_PLAY_NEXT:
            ohAVSessionCallbackImpl_->SetPlayNextCallback((OH_AVSession*)this, command, callback, userData);
            break;
        case CONTROL_CMD_PLAY_PREVIOUS:
            ohAVSessionCallbackImpl_->SetPlayPreviousCallback((OH_AVSession*)this, command, callback, userData);
            break;
        case CONTROL_CMD_INVALID:
        default:
            break;
    }
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVSession::UnregisterCommandCallback(AVSession_ControlCommand command,
    OH_AVSessionCallback_OnCommand callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(command));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    switch (command) {
        case CONTROL_CMD_PLAY:
            ohAVSessionCallbackImpl_->UnSetPlayCallback((OH_AVSession*)this, command, callback);
            break;
        case CONTROL_CMD_PAUSE:
            ohAVSessionCallbackImpl_->UnSetPauseCallback((OH_AVSession*)this, command, callback);
            break;
        case CONTROL_CMD_STOP:
            ohAVSessionCallbackImpl_->UnSetStopCallback((OH_AVSession*)this, command, callback);
            break;
        case CONTROL_CMD_PLAY_NEXT:
            ohAVSessionCallbackImpl_->UnSetPlayNextCallback((OH_AVSession*)this, command, callback);
            break;
        case CONTROL_CMD_PLAY_PREVIOUS:
            ohAVSessionCallbackImpl_->UnSetPlayPreviousCallback((OH_AVSession*)this, command, callback);
            break;
        case CONTROL_CMD_INVALID:
        default:
            break;
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::CheckAndRegister()
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        ohAVSessionCallbackImpl_ = std::make_shared<OHAVSessionCallbackImpl>();
        AVSession_ErrCode ret =  static_cast<AVSession_ErrCode>(
            avSession_->RegisterCallback(ohAVSessionCallbackImpl_));
        CHECK_AND_RETURN_RET_LOG(ret == AV_SESSION_ERR_SUCCESS, AV_SESSION_ERR_SERVICE_EXCEPTION,
            "RegisterCallback failed");
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::RegisterForwardCallback(OH_AVSessionCallback_OnFastForward callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    int32_t ret = avSession_->AddSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_FAST_FORWARD));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->RegisterForwardCallback((OH_AVSession*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterForwardCallback(OH_AVSessionCallback_OnFastForward callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_FAST_FORWARD));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->UnregisterForwardCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::RegisterRewindCallback(OH_AVSessionCallback_OnRewind callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    int32_t ret = avSession_->AddSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_REWIND));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->RegisterRewindCallback((OH_AVSession*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterRewindCallback(OH_AVSessionCallback_OnRewind callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_REWIND));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->UnregisterRewindCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::RegisterSeekCallback(OH_AVSessionCallback_OnSeek callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    int32_t ret = avSession_->AddSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_SEEK));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->RegisterSeekCallback((OH_AVSession*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterSeekCallback(OH_AVSessionCallback_OnSeek callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_SEEK));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->UnregisterSeekCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::RegisterSetLoopModeCallback(OH_AVSessionCallback_OnSetLoopMode callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    int32_t ret = avSession_->AddSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_SET_LOOP_MODE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->RegisterSetLoopModeCallback((OH_AVSession*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterSetLoopModeCallback(OH_AVSessionCallback_OnSetLoopMode callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_SET_LOOP_MODE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->UnregisterSetLoopModeCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::RegisterToggleFavoriteCallback(OH_AVSessionCallback_OnToggleFavorite callback,
    void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    int32_t ret = avSession_->AddSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->RegisterToggleFavoriteCallback((OH_AVSession*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterToggleFavoriteCallback(OH_AVSessionCallback_OnToggleFavorite callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = avSession_->DeleteSupportCommand(static_cast<int32_t>(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ohAVSessionCallbackImpl_->UnregisterToggleFavoriteCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}
}

AVSession_ErrCode OH_AVSession_Create(AVSession_Type sessionType, const char* sessionTag,
    const char* bundleName, const char* abilityName, OH_AVSession** avsession)
{
    switch (sessionType) {
        case SESSION_TYPE_AUDIO:
        case SESSION_TYPE_VIDEO:
        case SESSION_TYPE_VOICE_CALL:
        case SESSION_TYPE_VIDEO_CALL:
            break;
        default:
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = new OHOS::AVSession::OHAVSession(sessionType, sessionTag,
        bundleName, abilityName);
    if (oh_avsession->IsAVSessionNull()) {
        delete oh_avsession;
        oh_avsession = nullptr;
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    *avsession = (OH_AVSession*)oh_avsession;
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_Destroy(OH_AVSession* avsession)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    if (nullptr != oh_avsession) {
        delete oh_avsession;
        oh_avsession = nullptr;
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_Activate(OH_AVSession* avsession)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->Activate();
}

AVSession_ErrCode OH_AVSession_Deactivate(OH_AVSession* avsession)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->Deactivate();
}

AVSession_ErrCode OH_AVSession_GetSessionType(OH_AVSession* avsession, AVSession_Type* sessionType)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    std::string str = oh_avsession->GetSessionType();
    auto it = oh_avsession->avsessionTypes.find(str);
    if (it == oh_avsession->avsessionTypes.end()) {
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    *sessionType = it->second;
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_GetSessionId(OH_AVSession* avsession, const char** sessionId)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    *sessionId = oh_avsession->GetSessionId().c_str();
    return AV_SESSION_ERR_SUCCESS;
}

__attribute__((no_sanitize("cfi"))) AVSession_ErrCode OH_AVSession_SetAVMetadata(OH_AVSession* avsession,
                                                                                 OH_AVMetadata* metadata)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVMetadata is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetAVMetaData(metadata);
}

AVSession_ErrCode OH_AVSession_SetPlaybackState(OH_AVSession* avsession, AVSession_PlaybackState playbackState)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    switch (playbackState) {
        case PLAYBACK_STATE_INITIAL:
        case PLAYBACK_STATE_PREPARING:
        case PLAYBACK_STATE_PLAYING:
        case PLAYBACK_STATE_PAUSED:
        case PLAYBACK_STATE_FAST_FORWARDING:
        case PLAYBACK_STATE_REWINDED:
        case PLAYBACK_STATE_STOPPED:
        case PLAYBACK_STATE_COMPLETED:
        case PLAYBACK_STATE_RELEASED:
        case PLAYBACK_STATE_ERROR:
        case PLAYBACK_STATE_IDLE:
        case PLAYBACK_STATE_BUFFERING:
            break;
        default:
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetPlaybackState(playbackState);
}

AVSession_ErrCode OH_AVSession_SetPlaybackPosition(OH_AVSession* avsession,
    AVSession_PlaybackPosition* playbackPosition)
{
    if (avsession == nullptr || playbackPosition == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetPlaybackPosition(playbackPosition);
}

__attribute__((no_sanitize("cfi"))) AVSession_ErrCode OH_AVSession_SetFavorite(OH_AVSession* avsession,
                                                                               bool favorite)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetFavorite(favorite);
}

AVSession_ErrCode OH_AVSession_SetLoopMode(OH_AVSession* avsession, AVSession_LoopMode loopMode)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    switch (loopMode) {
        case LOOP_MODE_SEQUENCE:
        case LOOP_MODE_SINGLE:
        case LOOP_MODE_LIST:
        case LOOP_MODE_SHUFFLE:
        case LOOP_MODE_CUSTOM:
            break;
        default:
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetLoopMode(loopMode);
}

AVSession_ErrCode OH_AVSession_RegisterCommandCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    switch (command) {
        case CONTROL_CMD_PLAY:
        case CONTROL_CMD_PAUSE:
        case CONTROL_CMD_STOP:
        case CONTROL_CMD_PLAY_NEXT:
        case CONTROL_CMD_PLAY_PREVIOUS:
            break;
        default:
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return  oh_avsession->RegisterCommandCallback(command, callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterCommandCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    switch (command) {
        case CONTROL_CMD_PLAY:
        case CONTROL_CMD_PAUSE:
        case CONTROL_CMD_STOP:
        case CONTROL_CMD_PLAY_NEXT:
        case CONTROL_CMD_PLAY_PREVIOUS:
            break;
        default:
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterCommandCallback(command, callback);
}

AVSession_ErrCode OH_AVSession_RegisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterForwardCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterForwardCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnRewind callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterRewindCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnRewind callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterRewindCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterSeekCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterSeekCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterSetLoopModeCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterSetLoopModeCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback, void* userData)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterToggleFavoriteCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback)
{
    if (avsession == nullptr) {
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterToggleFavoriteCallback(callback);
}