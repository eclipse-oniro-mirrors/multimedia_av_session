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
#include "OHAVCastController.h"
#include "OHAVSession.h"
#include "OHDeviceInfo.h"
#include "OHAVUtils.h"
#include "avmeta_data.h"
#include "avsession_manager.h"

#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS::AVSession {
std::mutex g_setAVMetaDataMutex;
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
    dataTracker_ = std::make_shared<AVSessionDataTracker>();
}

void OHAVSession::SetAVSession(const std::shared_ptr<AVSession> &avsession)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    avSession_ = avsession;
    dataTracker_ = std::make_shared<AVSessionDataTracker>();
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

const std::string& OHAVSession::GetSessionId()
{
    if (sessionId_.empty()) {
        sessionId_ = avSession_->GetSessionId();
    }
    return sessionId_;
}

void OHAVSession::DownloadAndSetAVMetaData(std::shared_ptr<AVSession> avSession, AVMetaData data,
    std::shared_ptr<AVSessionDataTracker> dataTracker)
{
    if (avSession == nullptr || dataTracker == nullptr) {
        SLOGE("DownloadAndSetAVMetaData failed because session or tracker is nullptr");
        return;
    }

    int32_t ret = AVSessionNdkUtils::DownloadAndSetCoverImage(data.GetMediaImageUri(), data);
    SLOGI("DownloadAndSetAVMetaData uriSize:%{public}d complete with ret:%{public}d|%{public}d",
        static_cast<int>(data.GetMediaImageUri().size()), ret, data.GetMediaImageTopic());
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("DownloadAndSetAVMetaData failed but not repeat setmetadata again");
        return;
    }

    std::lock_guard<std::mutex> lockGuard(g_setAVMetaDataMutex);
    bool isOutOfDate = dataTracker->IsOutOfDate(data.GetAssetId(), data.GetMediaImageUri());
    SLOGI("DownloadAndSetAVMetaData ret:%{public}d|%{public}d", static_cast<int>(ret), isOutOfDate);
    if (!isOutOfDate) {
        dataTracker->OnDownloadCompleted(data.GetAssetId(), data.GetMediaImageUri());
        avSession->SetAVMetaData(data);
    }
}

AVSession_ErrCode OHAVSession::SetAVMetaData(OH_AVMetadata* metadata)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "metadata is nullptr");
    CHECK_AND_RETURN_RET_LOG(avSession_ != nullptr, AV_SESSION_ERR_SERVICE_EXCEPTION, "avSession_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataTracker_ != nullptr, AV_SESSION_ERR_SERVICE_EXCEPTION, "dataTracker_ is nullptr");

    AVMetaData *avMetaData = (AVMetaData*)metadata;
    if (metaData_.EqualWithUri(*avMetaData)) {
        SLOGI("metadata all same");
        return AV_SESSION_ERR_SUCCESS;
    }

    metaData_ = *avMetaData;
    dataTracker_->OnDataUpdated(metaData_.GetAssetId(), metaData_.GetMediaImageUri(),
        metaData_.GetMediaImage() != nullptr);
    bool isDownloadNeeded = dataTracker_->IsDownloadNeeded();
    int32_t ret = avSession_->SetAVMetaData(metaData_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, GetEncodeErrcode(ret), "SetAVMetaData fail:%{public}d", ret);

    if (!avMetaData->GetMediaImageUri().empty() && isDownloadNeeded && avMetaData->GetMediaImage() == nullptr) {
        AVSessionDownloadHandler::GetInstance().AVSessionDownloadRemoveTask("OHAVSession::SetAVMetaData");
        CHECK_AND_PRINT_LOG(AVSessionDownloadHandler::GetInstance().AVSessionDownloadPostTask(
            [avSession = avSession_, data = (*avMetaData), dataTracker = dataTracker_] {
                DownloadAndSetAVMetaData(avSession, data, dataTracker);
            }, "OHAVSession::SetAVMetaData"), "OHAVSession SetAVMetaData handler postTask failed");
    }

    return AV_SESSION_ERR_SUCCESS;
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

AVSession_ErrCode OHAVSession::SetFavorite(bool favorite)
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

AVSession_ErrCode OHAVSession::SetRemoteCastEnabled(bool enabled)
{
    AAFwk::WantParams extra;

    if (enabled) {
        extra.SetParam("requireAbilityList", OHOS::AAFwk::String::Box("url-cast"));
    }

    int32_t ret = avSession_->SetExtras(extra);
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

AVSession_ErrCode OHAVSession::RegisterOutputDeviceChangeCallback(OH_AVSessionCallback_OutputDeviceChange callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CheckAndRegister();
    ohAVSessionCallbackImpl_->RegisterOutputDeviceChangeCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::UnregisterOutputDeviceChangeCallback(OH_AVSessionCallback_OutputDeviceChange callback)
{
    if (ohAVSessionCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    ohAVSessionCallbackImpl_->UnregisterOutputDeviceChangeCallback((OH_AVSession*)this, callback);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::GetAVCastController(OHAVCastController **avcastController)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (IsAVSessionNull()) {
        SLOGE("avsession is not exist");
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }

    std::shared_ptr<AVCastController> controller = avSession_->GetAVCastController();
    if (controller == nullptr) {
        SLOGE("get controller fail");
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }

    OHAVCastController *avCastControllerObj = new OHAVCastController();
    if (avCastControllerObj == nullptr) {
        SLOGE("create avCastControllerObj fail");
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    avCastControllerObj->SetAVCastController(controller);

    *avcastController = avCastControllerObj;
    return AV_SESSION_ERR_SUCCESS;
#else
    return AV_SESSION_ERR_SERVICE_EXCEPTION;
#endif
}

AVSession_ErrCode OHAVSession::StopCasting()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (IsAVSessionNull()) {
        SLOGE("avsession is not exist");
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }

    int32_t ret = avSession_->ReleaseCast();
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("release cast fail");
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    return AV_SESSION_ERR_SUCCESS;
#else
    return AV_SESSION_ERR_SERVICE_EXCEPTION;
#endif
}

void OHAVSession::DestroyAVSessionOutputDevice(AVSession_OutputDeviceInfo *array)
{
    if (array) {
        for (uint32_t index = 0; index < array->size; index++) {
            AVSession_OutputDeviceInfo* outputDeviceInfo =
                (AVSession_OutputDeviceInfo*)array->deviceInfos[index];
            delete outputDeviceInfo;
            array->deviceInfos[index] = nullptr;
        }
        free(array->deviceInfos);
        free(array);
    }
}

AVSession_ErrCode OHAVSession::GetOutputDevice(AVSession_OutputDeviceInfo **outputDeviceInfo)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (IsAVSessionNull()) {
        SLOGE("avsession is not exist");
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }
    OutputDeviceInfo outputDeviceInfoVec;
    AVSessionDescriptor descriptor;
    AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(avSession_->GetSessionId(), descriptor);

    outputDeviceInfoVec = descriptor.outputDeviceInfo_;
    size_t size = outputDeviceInfoVec.deviceInfos_.size();
    if (size == 0) {
        SLOGE("outputDeviceInfoVec is empty");
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    *outputDeviceInfo = OHDeviceInfo::ConvertDesc(outputDeviceInfoVec);
    if ((*outputDeviceInfo) == nullptr) {
        SLOGE("convert output device info fail");
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::ReleaseOutputDevice(AVSession_OutputDeviceInfo *outputDeviceInfo)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    DestroyAVSessionOutputDevice(outputDeviceInfo);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSession::Destroy()
{
    avSession_->Destroy();
    return AV_SESSION_ERR_SUCCESS;
}
}

AVSession_ErrCode OH_AVSession_Create(AVSession_Type sessionType, const char* sessionTag,
    const char* bundleName, const char* abilityName, OH_AVSession** avsession)
{
    CHECK_AND_RETURN_RET_LOG(sessionTag != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "sessionTag is null");
    CHECK_AND_RETURN_RET_LOG(bundleName != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "bundleName is null");
    CHECK_AND_RETURN_RET_LOG(abilityName != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "abilityName is null");
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "avsession is null");

    switch (sessionType) {
        case SESSION_TYPE_AUDIO:
        case SESSION_TYPE_VIDEO:
        case SESSION_TYPE_VOICE_CALL:
        case SESSION_TYPE_VIDEO_CALL:
        case SESSION_TYPE_PHOTO:
            break;
        default:
            SLOGE("Invalid session type: %{public}d", sessionType);
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = new OHOS::AVSession::OHAVSession(sessionType, sessionTag,
        bundleName, abilityName);
    if (oh_avsession->IsAVSessionNull()) {
        delete oh_avsession;
        oh_avsession = nullptr;
        return AV_SESSION_ERR_SERVICE_EXCEPTION;
    }
    *avsession = (OH_AVSession*)oh_avsession;
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_Destroy(OH_AVSession* avsession)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    oh_avsession->Destroy();
    if (oh_avsession != nullptr) {
        delete oh_avsession;
        oh_avsession = nullptr;
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_Activate(OH_AVSession* avsession)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->Activate();
}

AVSession_ErrCode OH_AVSession_Deactivate(OH_AVSession* avsession)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->Deactivate();
}

AVSession_ErrCode OH_AVSession_GetSessionType(OH_AVSession* avsession, AVSession_Type* sessionType)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(sessionType != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "sessionType is null");

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
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(sessionId != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "sessionId is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    *sessionId = oh_avsession->GetSessionId().c_str();
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_SetAVMetadata(OH_AVSession* avsession, OH_AVMetadata* metadata)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(metadata != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVMetadata is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetAVMetaData(metadata);
}

AVSession_ErrCode OH_AVSession_SetPlaybackState(OH_AVSession* avsession, AVSession_PlaybackState playbackState)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

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
            SLOGE("Invalid playback state: %{public}d", playbackState);
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetPlaybackState(playbackState);
}

AVSession_ErrCode OH_AVSession_SetPlaybackPosition(OH_AVSession* avsession,
    AVSession_PlaybackPosition* playbackPosition)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(playbackPosition != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "playbackPosition is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetPlaybackPosition(playbackPosition);
}

AVSession_ErrCode OH_AVSession_SetFavorite(OH_AVSession* avsession, bool favorite)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetFavorite(favorite);
}

AVSession_ErrCode OH_AVSession_SetLoopMode(OH_AVSession* avsession, AVSession_LoopMode loopMode)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    switch (loopMode) {
        case LOOP_MODE_SEQUENCE:
        case LOOP_MODE_SINGLE:
        case LOOP_MODE_LIST:
        case LOOP_MODE_SHUFFLE:
        case LOOP_MODE_CUSTOM:
            break;
        default:
            SLOGE("Invalid loop mode: %{public}d", loopMode);
            return AV_SESSION_ERR_INVALID_PARAMETER;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetLoopMode(loopMode);
}

AVSession_ErrCode OH_AVSession_SetRemoteCastEnabled(OH_AVSession* avsession, bool enabled)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->SetRemoteCastEnabled(enabled);
}

AVSession_ErrCode OH_AVSession_RegisterCommandCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    switch (command) {
        case CONTROL_CMD_PLAY:
        case CONTROL_CMD_PAUSE:
        case CONTROL_CMD_STOP:
        case CONTROL_CMD_PLAY_NEXT:
        case CONTROL_CMD_PLAY_PREVIOUS:
            break;
        default:
            SLOGE("Invalid command: %{public}d", command);
            return AV_SESSION_ERR_CODE_COMMAND_INVALID;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return  oh_avsession->RegisterCommandCallback(command, callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterCommandCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    switch (command) {
        case CONTROL_CMD_PLAY:
        case CONTROL_CMD_PAUSE:
        case CONTROL_CMD_STOP:
        case CONTROL_CMD_PLAY_NEXT:
        case CONTROL_CMD_PLAY_PREVIOUS:
            break;
        default:
            SLOGE("Invalid command: %{public}d", command);
            return AV_SESSION_ERR_CODE_COMMAND_INVALID;
    }

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterCommandCallback(command, callback);
}

AVSession_ErrCode OH_AVSession_RegisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterForwardCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterForwardCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnRewind callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterRewindCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnRewind callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterRewindCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterSeekCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterSeekCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterSetLoopModeCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterSetLoopModeCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterToggleFavoriteCallback(callback, userData);
}

AVSession_ErrCode OH_AVSession_UnregisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterToggleFavoriteCallback(callback);
}

AVSession_ErrCode OH_AVSession_RegisterOutputDeviceChangeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OutputDeviceChange callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->RegisterOutputDeviceChangeCallback(callback);
}

AVSession_ErrCode OH_AVSession_UnregisterOutputDeviceChangeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OutputDeviceChange callback)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->UnregisterOutputDeviceChangeCallback(callback);
}

AVSession_ErrCode OH_AVSession_AcquireSession(const char* sessionTag, const char* bundleName, const char* abilityName,
    OH_AVSession** avsession)
{
    CHECK_AND_RETURN_RET_LOG(sessionTag != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "sessionTag is null");
    CHECK_AND_RETURN_RET_LOG(bundleName != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "bundleName is null");
    CHECK_AND_RETURN_RET_LOG(abilityName != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "abilityName is null");
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    std::shared_ptr<OHOS::AVSession::AVSession> session = nullptr;
    std::string tag = sessionTag;
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    OHOS::AVSession::AVSessionManager::GetInstance().GetSession(elementName, tag, session);
    if (session == nullptr) {
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }
    OHOS::AVSession::OHAVSession *oh_avsession = new OHOS::AVSession::OHAVSession();
    if (oh_avsession == nullptr) {
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }
    oh_avsession->SetAVSession(session);
    if (oh_avsession->IsAVSessionNull()) {
        delete oh_avsession;
        oh_avsession = nullptr;
        return AV_SESSION_ERR_CODE_SESSION_NOT_EXIST;
    }
    *avsession = (OH_AVSession *)oh_avsession;
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVSession_CreateAVCastController(OH_AVSession* avsession, OH_AVCastController** avcastcontroller)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "avcastcontroller is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    OHOS::AVSession::OHAVCastController **oh_avcastcontroller =
        (OHOS::AVSession::OHAVCastController **)(avcastcontroller);
    return oh_avsession->GetAVCastController(oh_avcastcontroller);
}

AVSession_ErrCode OH_AVSession_StopCasting(OH_AVSession* avsession)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->StopCasting();
}

AVSession_ErrCode OH_AVSession_AcquireOutputDevice(OH_AVSession* avsession,
    AVSession_OutputDeviceInfo** outputDeviceInfo)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(outputDeviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "outputDeviceInfo is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->GetOutputDevice(outputDeviceInfo);
}

AVSession_ErrCode OH_AVSession_ReleaseOutputDevice(OH_AVSession* avsession,
    AVSession_OutputDeviceInfo *outputDeviceInfo)
{
    CHECK_AND_RETURN_RET_LOG(avsession != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVSession is null");
    CHECK_AND_RETURN_RET_LOG(outputDeviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "outputDeviceInfo is null");

    OHOS::AVSession::OHAVSession *oh_avsession = (OHOS::AVSession::OHAVSession *)avsession;
    return oh_avsession->ReleaseOutputDevice(outputDeviceInfo);
}