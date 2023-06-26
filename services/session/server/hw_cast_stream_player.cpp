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

#include "avsession_log.h"
#include "avcast_player_state.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avsession_errors.h"
#include "hw_cast_stream_player.h"

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
    if (streamPlayer_) {
        SLOGI("register self in streamPlayer");
        streamPlayer_->RegisterListener(shared_from_this());
    }
}

void HwCastStreamPlayer::Release()
{
    SLOGI("Release the HwCastStreamPlayer");
    streamPlayerListenerList_.clear();
    if (streamPlayer_) {
        streamPlayer_->UnregisterListener();
        streamPlayer_->Release();
    }
}

void HwCastStreamPlayer::SendControlCommand(const AVCastControlCommand castControlCommand)
{
    SLOGI("send command to streamPlayer");
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return;
    }
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY:
            streamPlayer_ ->Play();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PAUSE:
            streamPlayer_ ->Pause();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_STOP:
            streamPlayer_ ->Stop();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT:
            streamPlayer_ ->Next();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS:
            streamPlayer_ ->Previous();
            break;
        default:
            SendControlCommandWithParams(castControlCommand);
            break;
    }
}

void HwCastStreamPlayer::SendControlCommandWithParams(const AVCastControlCommand castControlCommand)
{
    int32_t currentPosition = 0;
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
            streamPlayer_->GetPosition(currentPosition);
            int32_t forwardTime;
            castControlCommand.GetForwardTime(forwardTime);
            streamPlayer_ ->Seek(currentPosition + forwardTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
            streamPlayer_->GetPosition(currentPosition);
            int32_t rewindTime;
            castControlCommand.GetRewindTime(rewindTime);
            streamPlayer_ ->Seek(rewindTime > currentPosition ? 0 : currentPosition - rewindTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
            int32_t seekTime;
            castControlCommand.GetSeekTime(seekTime);
            streamPlayer_ ->Seek(seekTime);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME:
            int32_t volume;
            castControlCommand.GetVolume(volume);
            streamPlayer_ ->SetVolume(volume);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED:
            int32_t speed;
            castControlCommand.GetSpeed(speed);
            streamPlayer_ ->SetSpeed(static_cast<CastEngine::PlaybackSpeed>(speed));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE:
            int32_t loopMode;
            castControlCommand.GetLoopMode(loopMode);
            streamPlayer_ ->SetLoopMode(static_cast<CastEngine::LoopMode>(loopMode));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE:
            break;
        default:
            SLOGE("invalid command");
            break;
    }
}

int32_t HwCastStreamPlayer::Start(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = mediaDescription->GetMediaSize();
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    mediaInfo.albumCoverUrl = mediaDescription->GetAlbumCoverUri();
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();

    if (streamPlayer_ && streamPlayer_->Play(mediaInfo)) {
        SLOGI("Set media info and start successed");
        return AVSESSION_SUCCESS;
    }
    SLOGE("Set media info and start failed");
    return AVSESSION_ERROR;
}

int32_t HwCastStreamPlayer::Prepare(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = mediaDescription->GetMediaSize();
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    mediaInfo.albumCoverUrl = mediaDescription->GetAlbumCoverUri();
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();

    if (streamPlayer_ && streamPlayer_->Load(mediaInfo)) {
        SLOGI("Set media info and prepare successed");
        return AVSESSION_SUCCESS;
    }
    SLOGE("Set media info and prepare failed");
    return AVSESSION_ERROR;
}

int32_t HwCastStreamPlayer::GetDuration(int32_t& duration)
{
    SLOGI("GetDuration begin");
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
    streamPlayer_->GetVolume(castVolume);
    avPlaybackState.SetVolume(castVolume);
    SLOGI("GetCastAVPlaybackState successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::SetDisplaySurface(std::string &surfaceId)
{
    SLOGI("SetDisplaySurface begin");
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
    std::lock_guard<std::mutex> lock(mutex_);
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
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = streamPlayerListenerList_.begin(); iter != streamPlayerListenerList_.end();) {
        if (*iter == listener) {
            iter = streamPlayerListenerList_.erase(iter);
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
    AVPlaybackState avCastPlaybackState;
    AVPlaybackState::Position castPosition;
    castPosition.updateTime_ = position;
    avCastPlaybackState.SetPosition(castPosition);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPositionChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
}

void HwCastStreamPlayer::OnMediaItemChanged(const CastEngine::MediaInfo& mediaInfo)
{
    std::shared_ptr<AVMediaDescription> mediaDescription = std::make_shared<AVMediaDescription>();
    mediaDescription->SetMediaId(mediaInfo.mediaId);
    mediaDescription->SetTitle(mediaInfo.mediaName);
    mediaDescription->SetMediaUri(mediaInfo.mediaUrl);
    mediaDescription->SetMediaType(mediaInfo.mediaType);
    mediaDescription->SetMediaSize(mediaInfo.mediaSize);
    mediaDescription->SetStartPosition(static_cast<uint32_t>(mediaInfo.startPosition));
    mediaDescription->SetDuration(static_cast<uint32_t>(mediaInfo.duration));
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
}

void HwCastStreamPlayer::OnNextRequest()
{
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayNext for registered listeners");
            listener->OnPlayNext();
        }
    }
}

void HwCastStreamPlayer::OnPreviousRequest()
{
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayPrevious for registered listeners");
            listener->OnPlayPrevious();
        }
    }
}

void HwCastStreamPlayer::OnVolumeChanged(int volume)
{
    AVPlaybackState avCastPlaybackState;
    avCastPlaybackState.SetVolume(volume);
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
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayerError for registered listeners");
            listener->OnPlayerError(errorCode, errorMsg);
        }
    }
}

void HwCastStreamPlayer::OnVideoSizeChanged(int width, int height)
{
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVideoSizeChange for registered listeners");
            listener->OnVideoSizeChange(width, height);
        }
    }
}
} // namespace OHOS::AVSession
