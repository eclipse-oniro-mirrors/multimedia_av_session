/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hw_cast_stream_player.h"
#include "int_wrapper.h"
#include "avsession_log.h"
#include "avcast_player_state.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avsession_errors.h"

using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastStreamPlayer::~HwCastStreamPlayer()
{
    SLOGI("destruct the HwCastStreamPlayer");
    Release();
}

void HwCastStreamPlayer::Init()
{
    SLOGI("Init the HwCastStreamPlayer");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_) {
        SLOGI("register self in streamPlayer");
        streamPlayer_->RegisterListener(shared_from_this());
    }
}

void HwCastStreamPlayer::Release()
{
    SLOGI("Release the HwCastStreamPlayer");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_) {
        streamPlayer_->UnregisterListener();
        streamPlayer_->Release();
        streamPlayer_ = nullptr;
    }
    streamPlayerListenerList_.clear();
}

void HwCastStreamPlayer::SendControlCommand(const AVCastControlCommand castControlCommand)
{
    SLOGI("send command to streamPlayer");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return;
    }
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY:
            streamPlayer_->Play();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PAUSE:
            streamPlayer_->Pause();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_STOP:
            streamPlayer_->Stop();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT:
            streamPlayer_->Next();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS:
            streamPlayer_->Previous();
            break;
        default:
            SendControlCommandWithParams(castControlCommand);
            break;
    }
}

void HwCastStreamPlayer::SendControlCommandWithParams(const AVCastControlCommand castControlCommand)
{
    int32_t currentPosition = 0;
    std::lock_guard lockGuard(streamPlayerLock_);
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
            streamPlayer_->GetPosition(currentPosition);
            int32_t forwardTime;
            castControlCommand.GetForwardTime(forwardTime);
            streamPlayer_->Seek(currentPosition + forwardTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
            streamPlayer_->GetPosition(currentPosition);
            int32_t rewindTime;
            castControlCommand.GetRewindTime(rewindTime);
            streamPlayer_->Seek(rewindTime > currentPosition ? 0 : currentPosition - rewindTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
            int32_t seekTime;
            castControlCommand.GetSeekTime(seekTime);
            streamPlayer_->Seek(seekTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME:
            int32_t volume;
            castControlCommand.GetVolume(volume);
            streamPlayer_->SetVolume(volume);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED:
            int32_t speed;
            castControlCommand.GetSpeed(speed);
            streamPlayer_->SetSpeed(static_cast<CastEngine::PlaybackSpeed>(speed));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE:
            int32_t loopMode;
            castControlCommand.GetLoopMode(loopMode);
            streamPlayer_->SetLoopMode(static_cast<CastEngine::LoopMode>(loopMode + 1)); // Convert loop mode
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE:
            break;
        default:
            SLOGE("invalid command");
            break;
    }
}

AVQueueItem HwCastStreamPlayer::GetCurrentItem()
{
    std::lock_guard lockGuard(streamPlayerLock_);
    return currentAVQueueItem_;
}

int32_t HwCastStreamPlayer::Start(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    if (mediaDescription->GetMediaUri() == "") {
        if (mediaDescription->GetFdSrc().fd_ == 0) {
            SLOGW("No media id and fd src");
            mediaInfo.mediaUrl = "http:";
        } else {
            mediaInfo.mediaUrl = std::to_string(mediaDescription->GetFdSrc().fd_);
        }
    } else {
        mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    }
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = mediaDescription->GetMediaSize();
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    if (mediaDescription->GetIconUri() == "") {
        mediaInfo.albumCoverUrl = mediaDescription->GetAlbumCoverUri();
    } else {
        mediaInfo.albumCoverUrl = mediaDescription->GetIconUri();
    }
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();
    SLOGD("mediaInfo albumCoverUrl is %{public}s", mediaInfo.albumCoverUrl.c_str());
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    if (currentAVQueueItem_.GetDescription() && currentAVQueueItem_.GetDescription()->GetMediaUri() != "http:" &&
        currentAVQueueItem_.GetDescription()->GetMediaId() == mediaInfo.mediaId) {
        if (streamPlayer_->Play() != AVSESSION_SUCCESS) {
            SLOGE("Set media info and start failed");
            return AVSESSION_ERROR;
        }
    } else if (streamPlayer_->Play(mediaInfo) != AVSESSION_SUCCESS) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    currentAVQueueItem_ = avQueueItem;
    SLOGI("Set media info and start successfully");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::Prepare(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    if (mediaDescription->GetMediaUri() == "") {
        if (mediaDescription->GetFdSrc().fd_ == 0) {
            SLOGW("No media id and fd src");
            mediaInfo.mediaUrl = "http:";
            avQueueItem.GetDescription()->SetMediaUri("http:");
        } else {
            mediaInfo.mediaUrl = std::to_string(mediaDescription->GetFdSrc().fd_);
        }
    } else {
        mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    }
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = mediaDescription->GetMediaSize();
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    if (mediaDescription->GetIconUri() == "") {
        mediaInfo.albumCoverUrl = mediaDescription->GetAlbumCoverUri();
    } else {
        mediaInfo.albumCoverUrl = mediaDescription->GetIconUri();
    }
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();

    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_ && streamPlayer_->Load(mediaInfo) == AVSESSION_SUCCESS) {
        SLOGI("Set media info and prepare successed");
        currentAVQueueItem_ = avQueueItem;
        return AVSESSION_SUCCESS;
    }
    SLOGE("Set media info and prepare failed");
    return AVSESSION_ERROR;
}

int32_t HwCastStreamPlayer::GetDuration(int32_t& duration)
{
    SLOGI("GetDuration begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->GetDuration(duration);
    SLOGI("GetDuration successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetCastAVPlaybackState(AVPlaybackState& avPlaybackState)
{
    SLOGI("GetCastAVPlaybackState begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::PlayerStates castPlayerStates;
    streamPlayer_->GetPlayerStatus(castPlayerStates);
    if (castPlusStateToString_.count(castPlayerStates) != 0) {
        avPlaybackState.SetState(castPlusStateToString_[castPlayerStates]);
    }
    CastEngine::PlaybackSpeed castPlaybackSpeed;
    streamPlayer_->GetPlaySpeed(castPlaybackSpeed);
    if (castPlusSpeedToDouble_.count(castPlaybackSpeed) != 0) {
        avPlaybackState.SetSpeed(castPlusSpeedToDouble_[castPlaybackSpeed]);
    }
    int castPosition;
    streamPlayer_->GetPosition(castPosition);
    AVPlaybackState::Position position;
    position.updateTime_ = static_cast<int64_t>(castPosition);
    avPlaybackState.SetPosition(position);
    CastEngine::LoopMode castLoopMode;
    streamPlayer_->GetLoopMode(castLoopMode);
    if (castPlusLoopModeToInt_.count(castLoopMode) != 0) {
        avPlaybackState.SetLoopMode(castPlusLoopModeToInt_[castLoopMode]);
    }
    int32_t castVolume;
    int32_t maxCastVolume;
    streamPlayer_->GetVolume(castVolume, maxCastVolume);
    avPlaybackState.SetVolume(castVolume);

    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(maxCastVolume);
    if (wantParams == nullptr || intIt == nullptr) {
        return AVSESSION_ERROR;
    }
    wantParams->SetParam("maxCastVolume", intIt);
    avPlaybackState.SetExtras(wantParams);

    SLOGI("GetCastAVPlaybackState successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::SetDisplaySurface(std::string &surfaceId)
{
    SLOGI("SetDisplaySurface begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->SetSurface(surfaceId);
    SLOGI("SetDisplaySurface successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::RegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    SLOGI("RegisterControllerListener begin");
    if (listener == nullptr) {
        SLOGE("RegisterControllerListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(streamPlayerLock_);
    if (find(streamPlayerListenerList_.begin(), streamPlayerListenerList_.end(), listener)
        != streamPlayerListenerList_.end()) {
        SLOGE("listener is already in streamPlayerListenerList_");
        return AVSESSION_ERROR;
    }
    SLOGI("RegisterControllerListener successed, and add it to streamPlayerListenerList_");
    streamPlayerListenerList_.emplace_back(listener);

    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::UnRegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }
    std::lock_guard lockGuard(streamPlayerLock_);
    for (auto iter = streamPlayerListenerList_.begin(); iter != streamPlayerListenerList_.end();) {
        if (*iter == listener) {
            streamPlayerListenerList_.erase(iter);
            SLOGI("UnRegisterControllerListener successed, and erase it from streamPlayerListenerList_");
            return AVSESSION_SUCCESS;
        } else {
            ++iter;
        }
    }
    SLOGE("listener is not found in streamPlayerListenerList_, so UnRegisterControllerListener failed");

    return AVSESSION_ERROR;
}

void HwCastStreamPlayer::OnStateChanged(const CastEngine::PlayerStates playbackState, bool isPlayWhenReady)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusStateToString_.count(playbackState) == 0) {
        SLOGE("current playbackState status is not exist in castPlusStateToString_");
        avCastPlaybackState.SetState(AVPlaybackState::PLAYBACK_STATE_ERROR);
    } else {
        SLOGD("On state changed, get state %{public}d", castPlusStateToString_[playbackState]);
        avCastPlaybackState.SetState(castPlusStateToString_[playbackState]);
    }
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnCastPlaybackStateChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnPositionChanged(int position, int bufferPosition, int duration)
{
    if (position == -1 && bufferPosition == -1 && duration == -1) { // -1 is invalid(default) value
        SLOGW("Invalid position change callback");
        return;
    }
    AVPlaybackState avCastPlaybackState;
    if (position != -1) { // -1 is invalid position
        AVPlaybackState::Position castPosition;
        castPosition.elapsedTime_ = position;
        avCastPlaybackState.SetPosition(castPosition);
        SLOGD("Received elapsedTime: %{public}d", position);
    }
    if (bufferPosition != -1) { // -1 is invalid buffer position
        avCastPlaybackState.SetBufferedTime(bufferPosition);
        SLOGD("Received bufferPosition: %{public}d", bufferPosition);
    }
    if (duration != -1) {
        std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
        sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(duration);
        wantParams->SetParam("duration", intIt);
        avCastPlaybackState.SetExtras(wantParams);
        SLOGD("Received duration: %{public}d", duration);
    }
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPositionChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnMediaItemChanged(const CastEngine::MediaInfo& mediaInfo)
{
    SLOGD("Stream player received mediaItemChanged event");
    std::shared_ptr<AVMediaDescription> mediaDescription = std::make_shared<AVMediaDescription>();
    mediaDescription->SetMediaId(mediaInfo.mediaId);
    mediaDescription->SetTitle(mediaInfo.mediaName);
    mediaDescription->SetMediaUri(mediaInfo.mediaUrl);
    mediaDescription->SetMediaType(mediaInfo.mediaType);
    mediaDescription->SetMediaSize(mediaInfo.mediaSize);
    mediaDescription->SetStartPosition(static_cast<uint32_t>(mediaInfo.startPosition));
    mediaDescription->SetDuration(static_cast<uint32_t>(mediaInfo.duration));
    mediaDescription->SetCreditsPosition(static_cast<int32_t>(mediaInfo.closingCreditsPosition));
    mediaDescription->SetAlbumCoverUri(mediaInfo.albumCoverUrl);
    mediaDescription->SetAlbumTitle(mediaInfo.albumTitle);
    mediaDescription->SetArtist(mediaInfo.mediaArtist);
    mediaDescription->SetLyricUri(mediaInfo.lrcUrl);
    mediaDescription->SetIconUri(mediaInfo.appIconUrl);
    mediaDescription->SetAppName(mediaInfo.appName);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnMediaItemChange for registered listeners");
            listener->OnMediaItemChange(queueItem);
        }
    }
    std::lock_guard lockGuard(streamPlayerLock_);
    currentAVQueueItem_ = queueItem;
}

void HwCastStreamPlayer::OnNextRequest()
{
    SLOGD("StreamPlayer received next request");
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayNext for registered listeners");
            listener->OnPlayNext();
        }
    }
}

void HwCastStreamPlayer::OnPreviousRequest()
{
    SLOGD("StreamPlayer received previous request");
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayPrevious for registered listeners");
            listener->OnPlayPrevious();
        }
    }
}

void HwCastStreamPlayer::OnVolumeChanged(int volume, int maxVolume)
{
    SLOGD("StreamPlayer received volume changed event: %{public}d", volume);
    AVPlaybackState avCastPlaybackState;
    avCastPlaybackState.SetVolume(volume);

    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(maxVolume);
    if (wantParams == nullptr || intIt == nullptr) {
        return;
    }
    wantParams->SetParam("maxCastVolume", intIt);
    avCastPlaybackState.SetExtras(wantParams);

    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVolumeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnLoopModeChanged(const CastEngine::LoopMode loopMode)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusLoopModeToInt_.count(loopMode) == 0) {
        SLOGE("current playbackState status is not exist in castPlusStateToString_");
    } else {
        SLOGD("StreamPlayer received loop mode changed event: %{public}d", castPlusLoopModeToInt_[loopMode]);
        avCastPlaybackState.SetLoopMode(castPlusLoopModeToInt_[loopMode]);
    }
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnLoopModeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnPlaySpeedChanged(const CastEngine::PlaybackSpeed speed)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusSpeedToDouble_.count(speed) == 0) {
        SLOGE("current speed is not exist in castPlusSpeedToDouble_");
        return;
    }
    SLOGD("StreamPlayer received play speed changed event: %{public}f", castPlusSpeedToDouble_[speed]);
    avCastPlaybackState.SetSpeed(castPlusSpeedToDouble_[speed]);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPositionChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnPlayerError(int errorCode, const std::string &errorMsg)
{
    SLOGD("StreamPlayer received error event, code: %{public}d, message: %{public}s", errorCode, errorMsg.c_str());
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayerError for registered listeners");
            listener->OnPlayerError(errorCode, errorMsg);
        }
    }
}

void HwCastStreamPlayer::OnSeekDone(int32_t seekNumber)
{
    SLOGD("StreamPlayer received seek done event: %{public}d", seekNumber);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnSeekDone for registered listeners");
            listener->OnSeekDone(seekNumber);
        }
    }
}

void HwCastStreamPlayer::OnVideoSizeChanged(int width, int height)
{
    SLOGD("StreamPlayer received video size change event, width: %{public}d, height: %{public}d", width, height);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVideoSizeChange for registered listeners");
            listener->OnVideoSizeChange(width, height);
        }
    }
}

void HwCastStreamPlayer::OnEndOfStream(int isLooping)
{
    SLOGD("Received EndOfStream callback, value is %{public}d", isLooping);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnEndOfStream for registered listeners");
            listener->OnEndOfStream(isLooping);
        }
    }

    AVPlaybackState avCastPlaybackState;
    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(isLooping);
    if (wantParams == nullptr || intIt == nullptr) {
        return;
    }
    wantParams->SetParam("endofstream", intIt);
    avCastPlaybackState.SetExtras(wantParams);
    SLOGD("Received end of stream event: %{public}d", isLooping);

    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnEndOfStream for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}
} // namespace OHOS::AVSession
