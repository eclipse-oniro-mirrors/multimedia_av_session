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
    avQueueItem_ = std::make_shared<AVQueueItem>();
    avMediaDescription_ = std::make_shared<AVMediaDescription>();
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

AVSession_ErrCode OHAVCastController::RegisterPlaybackStateChangedCallback(
    OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData)
{
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
    playbackMask.set();
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

AVSession_ErrCode OHAVCastController::Prepare(OH_AVSession_AVQueueItem* avqueueItem)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("Prepare avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    avQueueItem_->SetItemId(static_cast<int32_t>(avqueueItem->itemId));
    if (avqueueItem->description == nullptr) {
        SLOGE("Description is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVMediaDescription *oh_description =
        (OHOS::AVSession::OHAVMediaDescription *)(avqueueItem->description);
    avMediaDescription_->SetMediaId(oh_description->GetAssetId());
    avMediaDescription_->SetTitle(oh_description->GetTitle());
    avMediaDescription_->SetSubtitle(oh_description->GetSubtitle());
    avMediaDescription_->SetArtist(oh_description->GetArtist());
    avMediaDescription_->SetMediaType(oh_description->GetMediaType());
    if (oh_description->GetMediaImage() != nullptr) {
        avMediaDescription_->SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(
            oh_description->GetMediaImage()->GetInnerPixelmap()));
    }
    avMediaDescription_->SetLyricContent(oh_description->GetLyricContent());
    avMediaDescription_->SetDuration(oh_description->GetDuration());
    avMediaDescription_->SetMediaUri(oh_description->GetMediaUri());
    avMediaDescription_->SetStartPosition(oh_description->GetStartPosition());
    avMediaDescription_->SetMediaSize(oh_description->GetMediaSize());
    avMediaDescription_->SetAlbumTitle(oh_description->GetAlbumTitle());
    avMediaDescription_->SetAppName(oh_description->GetAppName());
    avQueueItem_->SetDescription(avMediaDescription_);
    int32_t ret = avCastController_->Prepare(*(avQueueItem_.get()));
    if (ret != AVSESSION_SUCCESS) {
        return GetEncodeErrcode(ret);
    }
    std::thread([castController = avCastController_, queueItem = *(avQueueItem_.get())]() {
        std::lock_guard lockGuard(downloadPrepareMutex_);
        PrepareAsyncExecutor(castController, queueItem);
    }).detach();
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastController::Start(OH_AVSession_AVQueueItem* avqueueItem)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        SLOGE("Start avCastController_ is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    avQueueItem_->SetItemId(static_cast<int32_t>(avqueueItem->itemId));
    if (avqueueItem->description == nullptr) {
        SLOGE("Description is nullptr");
        return AV_SESSION_ERR_INVALID_PARAMETER;
    }
    OHOS::AVSession::OHAVMediaDescription *oh_description =
        (OHOS::AVSession::OHAVMediaDescription *)(avqueueItem->description);
    avMediaDescription_->SetMediaId(oh_description->GetAssetId());
    avMediaDescription_->SetTitle(oh_description->GetTitle());
    avMediaDescription_->SetSubtitle(oh_description->GetSubtitle());
    avMediaDescription_->SetArtist(oh_description->GetArtist());
    avMediaDescription_->SetMediaType(oh_description->GetMediaType());
    if (oh_description->GetMediaImage() != nullptr) {
        avMediaDescription_->SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(
            oh_description->GetMediaImage()->GetInnerPixelmap()));
    }
    avMediaDescription_->SetLyricContent(oh_description->GetLyricContent());
    avMediaDescription_->SetDuration(oh_description->GetDuration());
    avMediaDescription_->SetMediaUri(oh_description->GetMediaUri());
    avMediaDescription_->SetStartPosition(oh_description->GetStartPosition());
    avMediaDescription_->SetMediaSize(oh_description->GetMediaSize());
    avMediaDescription_->SetAlbumTitle(oh_description->GetAlbumTitle());
    avMediaDescription_->SetAppName(oh_description->GetAppName());
    avQueueItem_->SetDescription(avMediaDescription_);
    int32_t ret = avCastController_->Start(*(avQueueItem_.get()));
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

size_t OHAVCastController::WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb,
    std::vector<std::uint8_t> *imgBuffer)
{
    size_t realsize = 0;
    if (ptr == nullptr || size == realsize || nmemb == realsize || imgBuffer == nullptr) {
        SLOGE("WriteCallback parameter is invaild");
        return realsize;
    }
    realsize = size * nmemb;
    imgBuffer->reserve(realsize + imgBuffer->capacity());
    for (size_t i = 0; i < realsize; i++) {
        imgBuffer->push_back(ptr[i]);
    }
    return realsize;
}

int32_t OHAVCastController::DownloadCastImg(std::shared_ptr<AVMediaDescription> description, const std::string& uri)
{
    SLOGI("DownloadCastImg with title %{public}s", description->GetTitle().c_str());

    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    bool ret = OHAVCastController::DoDownloadInCommon(pixelMap, uri);
    SLOGI("DownloadCastImg with ret %{public}d, %{public}d",
        static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DownloadCastImg success");
        description->SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
        return AVSESSION_SUCCESS;
    }
    return AVSESSION_ERROR;
}

void OHAVCastController::PrepareAsyncExecutor(std::shared_ptr<AVCastController> avCastController,
    const AVQueueItem& data)
{
    CHECK_AND_RETURN_LOG(avCastController != nullptr, "prepare download but no castcontroller");
    SLOGI("do prepare set download");
    std::shared_ptr<AVMediaDescription> description = data.GetDescription();
    if (description == nullptr) {
        SLOGE("do prepare download image description is null");
        return;
    }
    auto uri = description->GetIconUri() == "" ?
        description->GetAlbumCoverUri() : description->GetIconUri();
    AVQueueItem item;
    if (description->GetIcon() == nullptr && !uri.empty()) {
        auto ret = DownloadCastImg(description, uri);
        SLOGI("DownloadCastImg complete with ret %{public}d", ret);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("DownloadCastImg failed but not repeat setmetadata again");
        } else {
            description->SetIconUri("URI_CACHE");
            item.SetDescription(description);
            if (avCastController == nullptr) {
                return;
            }
            auto prepareRet = avCastController->Prepare(item);
            SLOGI("do prepare set second with prepareret %{public}d", prepareRet);
        }
    }
}

bool OHAVCastController::CurlSetRequestOptions(std::vector<std::uint8_t>& imgBuffer, const std::string uri)
{
    CURL *easyHandle_ = curl_easy_init();
    if (easyHandle_) {
        // set request options
        curl_easy_setopt(easyHandle_, CURLOPT_URL, uri.c_str());
        curl_easy_setopt(easyHandle_, CURLOPT_CONNECTTIMEOUT, OHAVCastController::TIME_OUT_SECOND);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_CAINFO, "/etc/ssl/certs/" "cacert.pem");
        curl_easy_setopt(easyHandle_, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEFUNCTION, OHAVCastController::WriteCallback);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEDATA, &imgBuffer);

        // perform request
        CURLcode res = curl_easy_perform(easyHandle_);
        if (res != CURLE_OK) {
            SLOGI("DoDownload curl easy_perform failure: %{public}s\n", curl_easy_strerror(res));
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return false;
        } else {
            int64_t httpCode = 0;
            curl_easy_getinfo(easyHandle_, CURLINFO_RESPONSE_CODE, &httpCode);
            SLOGI("DoDownload Http result " "%{public}" PRId64, httpCode);
            CHECK_AND_RETURN_RET_LOG(httpCode < OHAVCastController::HTTP_ERROR_CODE, false, "recv Http ERROR");
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return true;
        }
    }
    return false;
}

bool OHAVCastController::DoDownloadInCommon(std::shared_ptr<Media::PixelMap>& pixelMap, const std::string uri)
{
    std::vector<std::uint8_t> imgBuffer(0);
    if (CurlSetRequestOptions(imgBuffer, uri) == true) {
        std::uint8_t* buffer = (std::uint8_t*) calloc(imgBuffer.size(), sizeof(uint8_t));
        if (buffer == nullptr) {
            SLOGE("buffer malloc fail");
            free(buffer);
            return false;
        }
        std::copy(imgBuffer.begin(), imgBuffer.end(), buffer);
        uint32_t errorCode = 0;
        Media::SourceOptions opts;
        SLOGD("DoDownload get size %{public}d", static_cast<int>(imgBuffer.size()));
        auto imageSource = Media::ImageSource::CreateImageSource(buffer, imgBuffer.size(), opts, errorCode);
        free(buffer);
        if (errorCode || !imageSource) {
            SLOGE("DoDownload create imageSource fail: %{public}u", errorCode);
            return false;
        }
        Media::DecodeOptions decodeOpts;
        pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        if (errorCode || pixelMap == nullptr) {
            SLOGE("DoDownload creatPix fail: %{public}u, %{public}d", errorCode, static_cast<int>(pixelMap != nullptr));
            return false;
        }
        return true;
    }
    return false;
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
    OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(avcastcontroller != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "AVCastController is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "callback is null");
    OHOS::AVSession::OHAVCastController *oh_avcastcontroller = (OHOS::AVSession::OHAVCastController *)avcastcontroller;
    return oh_avcastcontroller->RegisterPlaybackStateChangedCallback(callback, userData);
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