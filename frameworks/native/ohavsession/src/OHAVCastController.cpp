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

#include <thread>
#include "OHAVCastController.h"
#include "OHAVMetadataBuilder.h"
#include "OHAVUtils.h"
#include "avcast_control_command.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avsession_manager.h"
#include "avsession_pixel_map_adapter.h"

namespace OHOS::AVSession {

std::mutex OHAVCastController::downloadPrepareMutex_;

OHAVCastController::~OHAVCastController()
{
}

OHAVCastController::OHAVCastController()
{
    InitSharedPtrMember();
}

void OHAVCastController::InitSharedPtrMember()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    ohAVSessionPlaybackState_ = std::make_shared<OHAVSessionPlaybackState>();
    ohAVMediaDescription_ = std::make_shared<OHAVMediaDescription>();
    dataTracker_ = std::make_shared<AVSessionDataTracker>();
    avQueueItem_.SetDescription(std::make_shared<AVMediaDescription>());
}

bool OHAVCastController::SetAVCastController(std::shared_ptr<AVCastController> &castController)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (castController == nullptr) {
        return false;
    }

    avCastController_ = std::move(castController);
    return true;
}

AVSession_ErrCode OHAVCastController::Destroy()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("Destroy avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    avCastController_->Destroy();
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::GetPlaybackState(OH_AVSession_AVPlaybackState** playbackState)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("GetPlaybackState avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVPlaybackState avPlaybackState;
    int32_t ret = avCastController_->GetCastAVPlaybackState(avPlaybackState);
    if (ret != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }

    if (ohAVSessionPlaybackState_ == nullptr) {
        SLOGE("ohAVSessionPlaybackState is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    ohAVSessionPlaybackState_->SetState(avPlaybackState.GetState());
    AVPlaybackState::Position avPosition = avPlaybackState.GetPosition();
    OHAVSessionPlaybackState::Position position;
    position.elapsedTime_ = avPosition.elapsedTime_;
    position.updateTime_ = avPosition.updateTime_;
    ohAVSessionPlaybackState_->SetPosition(position);
    ohAVSessionPlaybackState_->SetSpeed(avPlaybackState.GetSpeed());
    ohAVSessionPlaybackState_->SetVolume(avPlaybackState.GetVolume());
    *playbackState = (OH_AVSession_AVPlaybackState *)(ohAVSessionPlaybackState_.get());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::RegisterPlaybackStateChangedCallback(int32_t filter,
    OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData)
{
    SLOGI("RegisterPlaybackStateChangedCallback filter:%{public}d", filter);
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("RegisterPlaybackStateChangedCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }

    AVPlaybackState::PlaybackStateMaskType playbackMask;
    OHAVSessionPlaybackState::ConvertFilter(filter, playbackMask);
    avCastController_->SetCastPlaybackFilter(playbackMask);
    ret = avCastController_->AddAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterPlaybackStateChangedCallback((OH_AVCastController*)this,
        callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterPlaybackStateChangedCallback(
    OH_AVCastControllerCallback_PlaybackStateChanged callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("UnregisterPlaybackStateChangedCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    int32_t ret = avCastController_->RemoveAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    return ohAVCastControllerCallbackImpl_->UnregisterPlaybackStateChangedCallback((OH_AVCastController*)this,
        callback);
}

AVSession_ErrCode OHAVCastController::RegisterMediaItemChangedCallback(
    OH_AVCastControllerCallback_MediaItemChange callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterMediaItemChangedCallback((OH_AVCastController*)this,
        callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterMediaItemChangedCallback(
    OH_AVCastControllerCallback_MediaItemChange callback)
{
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    return ohAVCastControllerCallbackImpl_->UnregisterMediaItemChangedCallback((OH_AVCastController*)this,
        callback);
}

AVSession_ErrCode OHAVCastController::RegisterPlayNextCallback(OH_AVCastControllerCallback_PlayNext callback,
    void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("RegisterPlayNextCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->AddAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterPlayNextCallback((OH_AVCastController*)this, callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterPlayNextCallback(OH_AVCastControllerCallback_PlayNext callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("UnregisterPlayNextCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    int32_t ret = avCastController_->RemoveAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    return ohAVCastControllerCallbackImpl_->UnregisterPlayNextCallback((OH_AVCastController*)this, callback);
}

AVSession_ErrCode OHAVCastController::RegisterPlayPreviousCallback(OH_AVCastControllerCallback_PlayPrevious callback,
    void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("RegisterPlayPreviousCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->AddAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterPlayPreviousCallback((OH_AVCastController*)this,
        callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterPlayPreviousCallback(OH_AVCastControllerCallback_PlayPrevious callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("UnregisterPlayPreviousCallback avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    int32_t ret = avCastController_->RemoveAvailableCommand(
        static_cast<int32_t>(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    return ohAVCastControllerCallbackImpl_->UnregisterPlayPreviousCallback((OH_AVCastController*)this, callback);
}

AVSession_ErrCode OHAVCastController::RegisterSeekDoneCallback(OH_AVCastControllerCallback_SeekDone callback,
    void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterSeekDoneCallback((OH_AVCastController*)this, callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterSeekDoneCallback(OH_AVCastControllerCallback_SeekDone callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    return ohAVCastControllerCallbackImpl_->UnregisterSeekDoneCallback((OH_AVCastController*)this, callback);
}

AVSession_ErrCode OHAVCastController::RegisterEndOfStreamCallback(OH_AVCastControllerCallback_EndOfStream callback,
    void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    ohAVCastControllerCallbackImpl_->RegisterEndOfStreamCallback((OH_AVCastController*)this, callback, userData);
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::UnregisterEndOfStreamCallback(OH_AVCastControllerCallback_EndOfStream callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    return ohAVCastControllerCallbackImpl_->UnregisterEndOfStreamCallback((OH_AVCastController*)this, callback);
}

AVSession_ErrCode OHAVCastController::RegisterErrorCallback(OH_AVCastControllerCallback_Error callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    int32_t ret = CheckAndRegister();
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        SLOGE("ohAVCastControllerCallbackImpl is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    return ohAVCastControllerCallbackImpl_->RegisterErrorCallback((OH_AVCastController*)this, callback, userData);
}

AVSession_ErrCode OHAVCastController::UnregisterErrorCallback(OH_AVCastControllerCallback_Error callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        return AV_SESSION_ERR_SUCCESS;
    }
    return ohAVCastControllerCallbackImpl_->UnregisterErrorCallback((OH_AVCastController*)this, callback);
}

AVSession_ErrCode OHAVCastController::SendCommonCommand(AVSession_AVCastControlCommandType *avCastControlCommand)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendCommonCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetCommand(*avCastControlCommand);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::SendSeekCommand(int32_t seekTimeMS)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendSeekCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetSeekTime(seekTimeMS);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = controlCommand.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::SendFastForwardCommand(int32_t forwardTimeS)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendFastForwardCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetForwardTime(forwardTimeS);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = controlCommand.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::SendRewindCommand(int32_t rewindTimeS)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendRewindCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetRewindTime(rewindTimeS);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = controlCommand.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::SendSetSpeedCommand(AVSession_PlaybackSpeed speed)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendSetSpeedCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetSpeed(static_cast<int32_t>(speed));
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = controlCommand.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::SendVolumeCommand(int32_t volume)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("SendVolumeCommand avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    AVCastControlCommand controlCommand;
    int32_t ret = controlCommand.SetVolume(volume);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = controlCommand.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    if (static_cast<AVSession_ErrCode>(ret) != AV_SESSION_ERR_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    ret = avCastController_->SendControlCommand(controlCommand);
    return GetEncodeErrcode(ret);
}

void OHAVCastController::UpdateAVQueueItem(const AVQueueItem &avQueueItem)
{
    if (avQueueItem_.GetDescription() == nullptr || avQueueItem.GetDescription() == nullptr) {
        return;
    }

    avQueueItem_.GetDescription()->SetMediaId(avQueueItem.GetDescription()->GetMediaId());
    avQueueItem_.GetDescription()->SetAlbumCoverUri(avQueueItem.GetDescription()->GetAlbumCoverUri());
    avQueueItem_.GetDescription()->SetMediaUri(avQueueItem.GetDescription()->GetMediaUri());
}

bool OHAVCastController::IsSameAVQueueItem(const AVQueueItem &avQueueItem)
{
    if (avQueueItem_.GetDescription() == nullptr || avQueueItem.GetDescription() == nullptr) {
        return false;
    }

    return avQueueItem_.GetDescription()->GetMediaId() == avQueueItem.GetDescription()->GetMediaId() &&
        avQueueItem_.GetDescription()->GetAlbumCoverUri() == avQueueItem.GetDescription()->GetAlbumCoverUri() &&
        avQueueItem_.GetDescription()->GetMediaUri() == avQueueItem.GetDescription()->GetMediaUri();
}

AVSession_ErrCode OHAVCastController::Prepare(OH_AVSession_AVQueueItem* avqueueItem)
{
    AVQueueItem avQueueItem;
    AVSession_ErrCode errCode = AVSessionNdkUtils::ConvertOHQueueItemToInner(avqueueItem, avQueueItem);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_SESSION_ERR_SUCCESS && avQueueItem.GetDescription() != nullptr,
        errCode, "ConvertOHQueueItemToInner fail");

    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_RET_LOG(avCastController_ != nullptr, AV_SESSION_ERR_SERVICE_EXCEPTION,
        "Prepare avCastController_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(dataTracker_ != nullptr, AV_SESSION_ERR_SERVICE_EXCEPTION, "dataTracker_ is nullptr");

    if (IsSameAVQueueItem(avQueueItem)) {
        SLOGI("avqueueItem all same");
        return AV_SESSION_ERR_SUCCESS;
    }

    UpdateAVQueueItem(avQueueItem);
    auto description = avQueueItem.GetDescription();

    dataTracker_->OnDataUpdated(description->GetMediaId(), description->GetAlbumCoverUri(),
        description->GetIcon() != nullptr);
    bool isDownloadNeeded = dataTracker_->IsDownloadNeeded();

    int32_t ret = avCastController_->Prepare(avQueueItem_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, GetEncodeErrcode(ret), "Prepare fail:%{public}d", ret);

    if (!description->GetAlbumCoverUri().empty() && isDownloadNeeded && description->GetIcon() == nullptr) {
        CHECK_AND_PRINT_LOG(AVSessionDownloadHandler::GetInstance().AVSessionDownloadPostTask(
            [castController = avCastController_, avQueueItem, dataTracker = dataTracker_]() {
                std::lock_guard lockGuard(downloadPrepareMutex_);
                PrepareAsyncExecutor(castController, avQueueItem, dataTracker);
            }, "OHAVCastController::Prepare"), "OHAVCastController Prepare handler postTask failed");
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::Start(OH_AVSession_AVQueueItem* avqueueItem)
{
    AVQueueItem avQueueItem;
    CHECK_AND_RETURN_RET_LOG(AVSessionNdkUtils::ConvertOHQueueItemToInner(avqueueItem, avQueueItem) ==
        AV_SESSION_ERR_SUCCESS, AV_SESSION_ERR_SERVICE_EXCEPTION, "ConvertOHQueueItemToInner fail");

    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("Start avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    int32_t ret = avCastController_->Start(avQueueItem);
    return GetEncodeErrcode(ret);
}

AVSession_ErrCode OHAVCastController::CheckAndRegister()
{
    if (avCastController_ == nullptr) {
        SLOGE("CheckAndRegister avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    if (ohAVCastControllerCallbackImpl_ == nullptr) {
        ohAVCastControllerCallbackImpl_ = std::make_shared<OHAVCastControllerCallbackImpl>();
        AVSession_ErrCode ret =  static_cast<AVSession_ErrCode>(
            avCastController_->RegisterCallback(ohAVCastControllerCallbackImpl_));
        CHECK_AND_RETURN_RET_LOG(ret == AV_SESSION_ERR_SUCCESS, AV_SESSION_ERR_SERVICE_EXCEPTION,
            "RegisterCallback failed");
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::GetEncodeErrcode(int32_t ret)
{
    auto it = errcodes.find(ret);
    if (it != errcodes.end()) {
        return it->second;
    }
    return AV_SESSION_ERR_SERVICE_EXCEPTION;
}

void OHAVCastController::PrepareAsyncExecutor(std::shared_ptr<AVCastController> avCastController,
    const AVQueueItem& data, std::shared_ptr<AVSessionDataTracker> dataTracker)
{
    std::shared_ptr<AVMediaDescription> description = data.GetDescription();
    CHECK_AND_RETURN_LOG(avCastController != nullptr, "prepare download but no castcontroller");
    CHECK_AND_RETURN_LOG(dataTracker != nullptr, "prepare download but dataTracker is null");
    CHECK_AND_RETURN_LOG(description != nullptr, "prepare download but image description is null");

    SLOGI("do prepare set download");
    std::string uri = description->GetAlbumCoverUri();
    if (description->GetIcon() != nullptr || uri.empty()) {
        SLOGI("prepare download but icon exist or uri empty");
        return;
    }

    int32_t ret = AVSessionNdkUtils::DownloadAndSetCastIcon(uri, description);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "DownloadCastImg failed but not repeat setmetadata again");
    bool isOutOfDate = dataTracker->IsOutOfDate(description->GetMediaId(), uri);
    SLOGI("DownloadAndSetCastIcon ret:%{public}d|%{public}d", static_cast<int>(ret), isOutOfDate);
    if (!isOutOfDate) {
        description->SetIconUri("URI_CACHE");
        AVQueueItem item;
        item.SetDescription(description);
        dataTracker->OnDownloadCompleted(description->GetMediaId(), uri);
        int32_t prepareRet = avCastController->Prepare(item);
        SLOGI("do prepare set second with prepareret %{public}d", prepareRet);
    }
}
} // OHOS::AVSession

AVSession_ErrCode OH_AVCastController_Destroy(OH_AVCastController* avcastcontroller)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");

    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    oh_avcastcontroller->Destroy();
    if (oh_avcastcontroller != nullptr) {
        delete oh_avcastcontroller;
        oh_avcastcontroller = nullptr;
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_AVCastController_GetPlaybackState(OH_AVCastController* avcastcontroller,
    OH_AVSession_AVPlaybackState** playbackState)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(playbackState != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "PlaybackState is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->GetPlaybackState(playbackState);
}

AVSession_ErrCode OH_AVCastController_RegisterPlaybackStateChangedCallback(OH_AVCastController* avcastcontroller,
    int32_t filter, OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterPlaybackStateChangedCallback(filter, callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterPlaybackStateChangedCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlaybackStateChanged callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterPlaybackStateChangedCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterMediaItemChangedCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_MediaItemChange callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterMediaItemChangedCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterMediaItemChangedCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_MediaItemChange callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterMediaItemChangedCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterPlayNextCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayNext callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterPlayNextCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterPlayNextCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayNext callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterPlayNextCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayPrevious callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterPlayPreviousCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayPrevious callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterPlayPreviousCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_SeekDone callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterSeekDoneCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_SeekDone callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterSeekDoneCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_EndOfStream callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterEndOfStreamCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_EndOfStream callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterEndOfStreamCallback(callback);
}

AVSession_ErrCode OH_AVCastController_RegisterErrorCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_Error callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterErrorCallback(callback, userData);
}

AVSession_ErrCode OH_AVCastController_UnregisterErrorCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_Error callback)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->UnregisterErrorCallback(callback);
}

AVSession_ErrCode OH_AVCastController_SendCommonCommand(OH_AVCastController* avcastcontroller,
    AVSession_AVCastControlCommandType *avCastControlcommand)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(avCastControlcommand != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastControlcommand is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendCommonCommand(avCastControlcommand);
}

AVSession_ErrCode OH_AVCastController_SendSeekCommand(OH_AVCastController* avcastcontroller, int32_t seekTimeMS)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendSeekCommand(seekTimeMS);
}

AVSession_ErrCode OH_AVCastController_SendFastForwardCommand(OH_AVCastController* avcastcontroller,
    int32_t forwardTimeS)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendFastForwardCommand(forwardTimeS);
}

AVSession_ErrCode OH_AVCastController_SendRewindCommand(OH_AVCastController* avcastcontroller, int32_t rewindTimeS)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendRewindCommand(rewindTimeS);
}

AVSession_ErrCode OH_AVCastController_SendSetSpeedCommand(OH_AVCastController* avcastcontroller,
    AVSession_PlaybackSpeed speed)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendSetSpeedCommand(speed);
}

AVSession_ErrCode OH_AVCastController_SendVolumeCommand(OH_AVCastController* avcastcontroller,
    int32_t volume)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->SendVolumeCommand(volume);
}

AVSession_ErrCode OH_AVCastController_Prepare(OH_AVCastController* avcastcontroller,
    OH_AVSession_AVQueueItem* avqueueItem)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(avqueueItem != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVqueueItem is null");

    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->Prepare(avqueueItem);
}

AVSession_ErrCode OH_AVCastController_Start(OH_AVCastController* avcastcontroller,
    OH_AVSession_AVQueueItem* avqueueItem)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(avqueueItem != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "AVqueueItem is null");

    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->Start(avqueueItem);
}