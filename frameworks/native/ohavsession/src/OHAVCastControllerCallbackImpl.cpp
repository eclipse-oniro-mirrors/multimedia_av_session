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

#include "OHAVCastControllerCallbackImpl.h"
#include "avsession_pixel_map_adapter.h"

namespace OHOS::AVSession {
OHAVCastControllerCallbackImpl::OHAVCastControllerCallbackImpl()
{
    InitSharedPtrMember();
}

OHAVCastControllerCallbackImpl::~OHAVCastControllerCallbackImpl()
{
}

void OHAVCastControllerCallbackImpl::InitSharedPtrMember()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    ohAVSessionPlaybackState_ = std::make_shared<OHAVSessionPlaybackState>();
    avMediaDescription_ = std::make_shared<AVMediaDescription>();
    ohAVMediaDescription_ = std::make_shared<OHAVMediaDescription>();
    ohAVSessionAVQueueItem_ = std::make_shared<OH_AVSession_AVQueueItem>();
}

void OHAVCastControllerCallbackImpl::OnCastPlaybackStateChange(const AVPlaybackState& state)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (playbackStateCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_PlaybackStateChanged");
        return;
    }
    for (auto it = playbackStateCallbacks_.begin(); it != playbackStateCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        ohAVSessionPlaybackState_->SetState(state.GetState());
        OHOS::AVSession::AVPlaybackState::Position position = state.GetPosition();
        OHOS::AVSession::OHAVSessionPlaybackState::Position avPosition;
        avPosition.elapsedTime_ = position.elapsedTime_;
        avPosition.updateTime_ = position.updateTime_;
        ohAVSessionPlaybackState_->SetPosition(avPosition);
        ohAVSessionPlaybackState_->SetSpeed(state.GetSpeed());
        ohAVSessionPlaybackState_->SetVolume(state.GetVolume());
        it->first(avCastController_, (OH_AVSession_AVPlaybackState *)(ohAVSessionPlaybackState_.get()), it->second);
    }
}

void OHAVCastControllerCallbackImpl::OnMediaItemChange(const AVQueueItem& avQueueItem)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (mediaItemChangedCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_MediaItemChange");
        return;
    }

    if (ohAVSessionAVQueueItem_ == nullptr) {
        SLOGE("ohAVSessionAVQueueItem is null");
        return;
    }
    if (ohAVMediaDescription_ == nullptr) {
        SLOGE("ohAVMediaDescription is null");
        return;
    }
    ohAVSessionAVQueueItem_->itemId = static_cast<uint32_t>(avQueueItem.GetItemId());
    avMediaDescription_ = avQueueItem.GetDescription();
    if (avMediaDescription_ == nullptr) {
        SLOGE("getDescription is null");
        return;
    }
    ohAVMediaDescription_->SetAssetId(avMediaDescription_->GetMediaId());
    ohAVMediaDescription_->SetTitle(avMediaDescription_->GetTitle());
    ohAVMediaDescription_->SetSubtitle(avMediaDescription_->GetSubtitle());
    ohAVMediaDescription_->SetArtist(avMediaDescription_->GetArtist());
    ohAVMediaDescription_->SetAlbumCoverUri(avMediaDescription_->GetAlbumCoverUri());
    ohAVMediaDescription_->SetMediaType(avMediaDescription_->GetMediaType());
    ohAVMediaDescription_->SetLyricContent(avMediaDescription_->GetLyricContent());
    ohAVMediaDescription_->SetDuration(avMediaDescription_->GetDuration());
    ohAVMediaDescription_->SetMediaUri(avMediaDescription_->GetMediaUri());
    ohAVMediaDescription_->SetStartPosition(avMediaDescription_->GetStartPosition());
    ohAVMediaDescription_->SetMediaSize(avMediaDescription_->GetMediaSize());
    ohAVMediaDescription_->SetAlbumTitle(avMediaDescription_->GetAlbumTitle());
    ohAVMediaDescription_->SetAppName(avMediaDescription_->GetAppName());
    ohAVSessionAVQueueItem_->description = (OH_AVSession_AVMediaDescription *)(ohAVMediaDescription_.get());

    for (auto it = mediaItemChangedCallbacks_.begin(); it != mediaItemChangedCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, ohAVSessionAVQueueItem_.get(), it->second);
    }
}

void OHAVCastControllerCallbackImpl::OnPlayNext()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (playNextCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_PlayNext");
        return;
    }
    for (auto it = playNextCallbacks_.begin(); it != playNextCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, it->second);
    }
}

void OHAVCastControllerCallbackImpl::OnPlayPrevious()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (playPreviousCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_PlayPrevious");
        return;
    }
    for (auto it = playPreviousCallbacks_.begin(); it != playPreviousCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, it->second);
    }
}

void OHAVCastControllerCallbackImpl::OnSeekDone(const int32_t seekNumber)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (seekDoneCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_SeekDone");
        return;
    }
    for (auto it = seekDoneCallbacks_.begin(); it != seekDoneCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, seekNumber, it->second);
    }
}

void OHAVCastControllerCallbackImpl::OnPlayerError(const int32_t errorCode, const std::string& errorMsg)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (errorCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_Error");
        return;
    }
    for (auto it = errorCallbacks_.begin(); it != errorCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, it->second, static_cast<AVSession_ErrCode>(errorCode));
    }
}

void OHAVCastControllerCallbackImpl::OnEndOfStream(const int32_t isLooping)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (endOfStreamCallbacks_.empty()) {
        SLOGE("not register OH_AVCastControllerCallback_EndOfStream");
        return;
    }
    for (auto it = endOfStreamCallbacks_.begin(); it != endOfStreamCallbacks_.end(); ++it) {
        if (it->first == nullptr || avCastController_ == nullptr) {
            continue;
        }
        it->first(avCastController_, it->second);
    }
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterPlaybackStateChangedCallback(
    OH_AVCastController* avcastcontroller, OH_AVCastControllerCallback_PlaybackStateChanged callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(playbackStateCallbacks_.begin(), playbackStateCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlaybackStateChanged, void*> &element) {
            return element.first == callback;
        });
    if (it == playbackStateCallbacks_.end()) {
        playbackStateCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterPlaybackStateChangedCallback(
    OH_AVCastController* avcastcontroller, OH_AVCastControllerCallback_PlaybackStateChanged callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(playbackStateCallbacks_.begin(), playbackStateCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlaybackStateChanged, void*> &element) {
            return element.first == callback;
        });
    playbackStateCallbacks_.erase(newEnd, playbackStateCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterMediaItemChangedCallback(
    OH_AVCastController* avcastcontroller, OH_AVCastControllerCallback_MediaItemChange callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(mediaItemChangedCallbacks_.begin(), mediaItemChangedCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_MediaItemChange, void*> &element) {
            return element.first == callback;
        });
    if (it == mediaItemChangedCallbacks_.end()) {
        mediaItemChangedCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterMediaItemChangedCallback(
    OH_AVCastController* avcastcontroller, OH_AVCastControllerCallback_MediaItemChange callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(mediaItemChangedCallbacks_.begin(), mediaItemChangedCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_MediaItemChange, void*> &element) {
            return element.first == callback;
        });
    mediaItemChangedCallbacks_.erase(newEnd, mediaItemChangedCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterPlayNextCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayNext callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(playNextCallbacks_.begin(), playNextCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlayNext, void*> &element) {
            return element.first == callback;
        });
    if (it == playNextCallbacks_.end()) {
        playNextCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterPlayNextCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayNext callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(playNextCallbacks_.begin(), playNextCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlayNext, void*> &element) {
            return element.first == callback;
        });
    playNextCallbacks_.erase(newEnd, playNextCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayPrevious callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(playPreviousCallbacks_.begin(), playPreviousCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlayPrevious, void*> &element) {
            return element.first == callback;
        });
    if (it == playPreviousCallbacks_.end()) {
        playPreviousCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterPlayPreviousCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_PlayPrevious callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(playPreviousCallbacks_.begin(), playPreviousCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_PlayPrevious, void*> &element) {
            return element.first == callback;
        });
    playPreviousCallbacks_.erase(newEnd, playPreviousCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_SeekDone callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(seekDoneCallbacks_.begin(), seekDoneCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_SeekDone, void*> &element) {
            return element.first == callback;
        });
    if (it == seekDoneCallbacks_.end()) {
        seekDoneCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterSeekDoneCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_SeekDone callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(seekDoneCallbacks_.begin(), seekDoneCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_SeekDone, void*> &element) {
            return element.first == callback;
        });
    seekDoneCallbacks_.erase(newEnd, seekDoneCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_EndOfStream callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(endOfStreamCallbacks_.begin(), endOfStreamCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_EndOfStream, void*> &element) {
            return element.first == callback;
        });
    if (it == endOfStreamCallbacks_.end()) {
        endOfStreamCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterEndOfStreamCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_EndOfStream callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(endOfStreamCallbacks_.begin(), endOfStreamCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_EndOfStream, void*> &element) {
            return element.first == callback;
        });
    endOfStreamCallbacks_.erase(newEnd, endOfStreamCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::RegisterErrorCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_Error callback, void* userData)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (avCastController_ == nullptr) {
        avCastController_ = avcastcontroller;
    }
    auto it = std::find_if(errorCallbacks_.begin(), errorCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_Error, void*> &element) {
            return element.first == callback;
        });
    if (it == errorCallbacks_.end()) {
        errorCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVCastControllerCallbackImpl::UnregisterErrorCallback(OH_AVCastController* avcastcontroller,
    OH_AVCastControllerCallback_Error callback)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    auto newEnd = std::remove_if(errorCallbacks_.begin(), errorCallbacks_.end(),
        [callback](const std::pair<OH_AVCastControllerCallback_Error, void*> &element) {
            return element.first == callback;
        });
    errorCallbacks_.erase(newEnd, errorCallbacks_.end());
    return AV_SESSION_ERR_SUCCESS;
}
}