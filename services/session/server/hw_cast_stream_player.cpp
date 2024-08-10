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
#include "avsession_sysevent.h"
#include "avsession_trace.h"
#include "avsession_radar.h"

using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastStreamPlayer::~HwCastStreamPlayer()
{
    SLOGI("destruct the HwCastStreamPlayer without release");
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

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    streamPlayerListenerList_.clear();
    SLOGI("Release the HwCastStreamPlayer done");
}

int32_t HwCastStreamPlayer::CheckCastTime(int32_t castTime)
{
    if (castTime < castMinTime) {
        return castMinTime * castTime;
    } else {
        return castTime;
    }
}

void HwCastStreamPlayer::SendControlCommand(const AVCastControlCommand castControlCommand)
{
    int32_t commandNum = castControlCommand.GetCommand();
    SLOGI("send command to streamPlayer %{public}d", static_cast<int32_t>(commandNum));
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "SESSION_TYPE", "cast",
            "ERROR_TYPE", "INNER_ERROR",
            "ERROR_INFO", "streamPlayer is nullptr");
        AVSessionRadarInfo info("HwCastStreamPlayer::SendControlCommand");
        info.errorCode_ = AVSessionRadar::GetRadarErrorCode(ERR_REMOTE_CONNECTION_NOT_EXIST);
        AVSessionRadar::GetInstance().FailToSendControlCommand(info);
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
    std::lock_guard lockGuard(streamPlayerLock_);
    int32_t timeParam;
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
            castControlCommand.GetForwardTime(timeParam);
            streamPlayer_->FastForward(CheckCastTime(timeParam));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
            castControlCommand.GetRewindTime(timeParam);
            streamPlayer_->FastRewind(CheckCastTime(timeParam));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
            castControlCommand.GetSeekTime(timeParam);
            streamPlayer_->Seek(timeParam);
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
            if (intLoopModeToCastPlus_.count(loopMode) != 0) {
                SLOGD("SetLoopMode int: %{public}d", loopMode);
                streamPlayer_->SetLoopMode(intLoopModeToCastPlus_[loopMode]);
            } else {
                SLOGE("invalid LoopMode: %{public}d", loopMode);
            }
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE:
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE:
            bool enableMute;
            streamPlayer_->GetMute(enableMute);
            streamPlayer_->SetMute(!enableMute);
            break;
        default:
            SLOGE("invalid command");
            HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED", "ERROR_TYPE", "INNER_ERROR", "ERROR_INFO", "invalid command");
            break;
    }
}

AVQueueItem HwCastStreamPlayer::GetCurrentItem()
{
    SLOGI("Received GetCurrentItem request");
    int32_t duration;
    GetDuration(duration);
    // do not place streamPlayerLock_ in side of curItemLock_
    std::lock_guard lockGuard(curItemLock_);
    std::shared_ptr<AVMediaDescription> mediaDescription = currentAVQueueItem_.GetDescription();
    if (mediaDescription == nullptr) {
        SLOGE("GetCurrentItem with nullptr, return with default");
        return currentAVQueueItem_;
    }
    mediaDescription->SetDuration(duration);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    currentAVQueueItem_ = queueItem;
    return currentAVQueueItem_;
}

int32_t HwCastStreamPlayer::RefreshCurrentAVQueueItem(const AVQueueItem& avQueueItem)
{
    std::lock_guard lockGuard(curItemLock_);
    std::shared_ptr<AVMediaDescription> originMediaDescription = currentAVQueueItem_.GetDescription();
    std::shared_ptr<AVMediaDescription> newMediaDescription = avQueueItem.GetDescription();
    if (originMediaDescription != nullptr &&
        originMediaDescription->GetIcon() != nullptr && newMediaDescription->GetIcon() == nullptr) {
        SLOGI("RefreshCurrentAVQueueItem with icon refresh");
        newMediaDescription->SetIcon(originMediaDescription->GetIcon());
    }
    currentAVQueueItem_ = avQueueItem;
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::Start(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    if (mediaDescription->GetMediaUri() == "") {
        if (mediaDescription->GetFdSrc().fd_ == 0) {
            SLOGW("No media id and fd src");
            mediaInfo.mediaUrl = "http:";
        } else {
            mediaInfo.mediaUrl = std::to_string(mediaDescription->GetFdSrc().fd_);
        }
    }
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = static_cast<uint32_t>(mediaDescription->GetMediaSize());
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    mediaInfo.albumCoverUrl = mediaDescription->GetIconUri() == "" ?
        mediaDescription->GetAlbumCoverUri() : mediaDescription->GetIconUri();
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();
    mediaInfo.drmType = mediaDescription->GetDrmScheme();
    std::lock_guard lockGuard(streamPlayerLock_);
    SLOGI("mediaInfo media is %{public}s %{public}s", mediaInfo.albumCoverUrl.c_str(), mediaInfo.mediaUrl.c_str());
    if (!streamPlayer_) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    std::shared_ptr<AVMediaDescription> originMediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        originMediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (originMediaDescription && originMediaDescription->GetMediaUri() != "http:" &&
        originMediaDescription->GetMediaId() == mediaInfo.mediaId) {
        CHECK_AND_RETURN_RET_LOG(streamPlayer_->Play() != AVSESSION_SUCCESS, AVSESSION_ERROR, "Set play failed");
    } else if (streamPlayer_->Play(mediaInfo) != AVSESSION_SUCCESS) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    RefreshCurrentAVQueueItem(avQueueItem);
    currentAlbumCoverUri_ = mediaInfo.albumCoverUrl;
    SLOGI("Set media info and start successfully");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::CheckBeforePrepare(std::shared_ptr<AVMediaDescription> mediaDescription)
{
    std::lock_guard lockGuard(curItemLock_);
    std::shared_ptr<AVMediaDescription> originMediaDescription = currentAVQueueItem_.GetDescription();

    if (mediaDescription->GetIconUri() != "INVALID_URI_CACHE") {
        SLOGI("prepare but not repeat, IconUri %{public}s", mediaDescription->GetIconUri().c_str());
        return AVSESSION_SUCCESS;
    } else if (originMediaDescription != nullptr &&
        originMediaDescription->GetMediaId() == mediaDescription->GetMediaId() &&
        mediaDescription->GetIcon() != nullptr && originMediaDescription->GetIcon() == nullptr) {
        SLOGW("prepare with repeatMediaId %{public}s", mediaDescription->GetMediaId().c_str());
        originMediaDescription->SetIcon(mediaDescription->GetIcon());

        {
            std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
            for (auto listener : streamPlayerListenerList_) {
                if (listener != nullptr) {
                    SLOGI("trigger the OnMediaItemChange for registered listeners");
                    listener->OnMediaItemChange(currentAVQueueItem_);
                }
            }
        }
        return AVSESSION_ERROR;
    }
    return AVSESSION_ERROR;
}

int32_t HwCastStreamPlayer::Prepare(const AVQueueItem& avQueueItem)
{
    CastEngine::MediaInfo mediaInfo;
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    SLOGI("do CheckBeforePrepare with mediaId %{public}s | title %{public}s",
        mediaInfo.mediaId.c_str(), mediaInfo.mediaName.c_str());
    if (CheckBeforePrepare(mediaDescription) != AVSESSION_SUCCESS) {
        return AVSESSION_SUCCESS;
    }
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
    mediaInfo.mediaSize = static_cast<uint32_t>(mediaDescription->GetMediaSize());
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
    mediaInfo.drmType = mediaDescription->GetDrmScheme();
    SLOGD("mediaInfo albumCoverUrl is %{public}s", mediaInfo.albumCoverUrl.c_str());
    std::lock_guard lockGuard(streamPlayerLock_);
    SLOGI("pass playerlock, check item lock, mediaInfo mediaUrl is %{public}s", mediaInfo.mediaUrl.c_str());
    if (streamPlayer_ && streamPlayer_->Load(mediaInfo) == AVSESSION_SUCCESS) {
        std::lock_guard lockGuard(curItemLock_);
        SLOGI("Set media info and prepare with curItemLock successed");
        currentAVQueueItem_ = avQueueItem;
        currentAlbumCoverUri_ = mediaInfo.albumCoverUrl;
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
    position.elapsedTime_ = static_cast<int64_t>(castPosition);
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

    SLOGI("GetCastAVPlaybackState successed with state: %{public}d", avPlaybackState.GetState());
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

int32_t HwCastStreamPlayer::ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response)
{
    SLOGI("ProcessMediaKeyResponse begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->ProvideKeyResponse(assetId, response);
    SLOGI("ProcessMediaKeyResponse successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::RegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    SLOGI("RegisterControllerListener begin");
    if (listener == nullptr) {
        SLOGE("RegisterControllerListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    if (find(streamPlayerListenerList_.begin(), streamPlayerListenerList_.end(), listener)
        != streamPlayerListenerList_.end()) {
        SLOGE("listener is already in streamPlayerListenerList_");
        return AVSESSION_ERROR;
    }
    SLOGI("RegisterControllerListener successed, and add it to streamPlayerListenerList_");
    streamPlayerListenerList_.emplace_back(listener);
    SLOGI("RegisterControllerListener done with size %{public}d", static_cast<int>(streamPlayerListenerList_.size()));
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::UnRegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
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

int32_t HwCastStreamPlayer::GetValidAbility(std::vector<int32_t>& validCmdList)
{
    SLOGI("GetValidAbility in");
    if (streamPlayer_ == nullptr) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::StreamCapability streamCapability;
    streamPlayer_->GetAvailableCapability(streamCapability);
    checkCmdsFromAbility(streamCapability, validCmdList);
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::SetValidAbility(const std::vector<int32_t>& validCmdList)
{
    SLOGI("SetValidAbility begin");
    if (streamPlayer_ == nullptr) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::StreamCapability streamCapability;
    checkAbilityFromCmds(validCmdList, streamCapability);
    streamPlayer_->SetAvailableCapability(streamCapability);
    return AVSESSION_SUCCESS;
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
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnCastPlaybackStateChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("on cast state change done");
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
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPositionChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("on cast position change done");
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
    mediaDescription->SetAlbumCoverUri(currentAlbumCoverUri_);
    mediaDescription->SetAlbumTitle(mediaInfo.albumTitle);
    mediaDescription->SetArtist(mediaInfo.mediaArtist);
    mediaDescription->SetLyricUri(mediaInfo.lrcUrl);
    mediaDescription->SetIconUri(mediaInfo.appIconUrl);
    mediaDescription->SetAppName(mediaInfo.appName);
    mediaDescription->SetDrmScheme(mediaInfo.drmType);
    std::shared_ptr<AVMediaDescription> originMediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        originMediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (originMediaDescription != nullptr && originMediaDescription->GetIcon() != nullptr
        && mediaInfo.mediaId == originMediaDescription->GetMediaId()) {
        SLOGI("mediaItemChanged with origin icon set");
        mediaDescription->SetIcon(originMediaDescription->GetIcon());
    }
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    {
        std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
        for (auto listener : streamPlayerListenerList_) {
            if (listener != nullptr) {
                SLOGI("trigger the OnMediaItemChange for registered listeners");
                listener->OnMediaItemChange(queueItem);
            }
        }
    }
    {
        std::lock_guard lockGuard(curItemLock_);
        currentAVQueueItem_ = queueItem;
    }

    SLOGI("StreamPlayer received mediaItemChanged event done");
}

void HwCastStreamPlayer::OnNextRequest()
{
    SLOGD("StreamPlayer received next request");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayNext for registered listeners");
            listener->OnPlayNext();
        }
    }
    SLOGI("StreamPlayer received next request done");
}

void HwCastStreamPlayer::OnPreviousRequest()
{
    SLOGD("StreamPlayer received previous request");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayPrevious for registered listeners");
            listener->OnPlayPrevious();
        }
    }
    SLOGI("StreamPlayer received previous request done");
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

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVolumeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("StreamPlayer received volume changed event done: %{public}d", volume);
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
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnLoopModeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("loop mode changed event done: %{public}d", castPlusLoopModeToInt_[loopMode]);
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
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPositionChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("play speed changed event done: %{public}f", castPlusSpeedToDouble_[speed]);
}

void HwCastStreamPlayer::OnPlayerError(int errorCode, const std::string &errorMsg)
{
    SLOGD("StreamPlayer received error event, code: %{public}d, message: %{public}s", errorCode, errorMsg.c_str());
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayerError for registered listeners");
            listener->OnPlayerError(errorCode, errorMsg);
        }
    }
    SLOGI("error event done, code: %{public}d, message: %{public}s", errorCode, errorMsg.c_str());
}

void HwCastStreamPlayer::OnSeekDone(int32_t seekNumber)
{
    SLOGD("StreamPlayer received seek done event: %{public}d", seekNumber);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnSeekDone for registered listeners");
            listener->OnSeekDone(seekNumber);
        }
    }
    SLOGI("StreamPlayer received seek done event done with: %{public}d", seekNumber);
}

void HwCastStreamPlayer::OnVideoSizeChanged(int width, int height)
{
    SLOGD("StreamPlayer received video size change event, width: %{public}d, height: %{public}d", width, height);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVideoSizeChange for registered listeners");
            listener->OnVideoSizeChange(width, height);
        }
    }
    SLOGI("video size change event done, width: %{public}d, height: %{public}d", width, height);
}

void HwCastStreamPlayer::OnEndOfStream(int isLooping)
{
    SLOGD("Received EndOfStream callback, value is %{public}d", isLooping);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
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
    SLOGI("Received EndOfStream callback done, value is %{public}d", isLooping);
}

void HwCastStreamPlayer::OnPlayRequest(const CastEngine::MediaInfo& mediaInfo)
{
    SLOGI("Stream player received PlayRequest event");
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
    mediaDescription->SetDrmScheme(mediaInfo.drmType);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayRequest for registered listeners");
            listener->OnPlayRequest(queueItem);
        }
    }
    SLOGI("Stream player received PlayRequest event done");
}

void HwCastStreamPlayer::OnImageChanged(std::shared_ptr<Media::PixelMap> pixelMap)
{
    SLOGD("Stream player received ImageChanged event");
}

void HwCastStreamPlayer::OnAlbumCoverChanged(std::shared_ptr<Media::PixelMap> pixelMap)
{
    SLOGI("Received AlbumCoverChanged callback");
    if (pixelMap == nullptr) {
        SLOGE("Invalid pixelMap null");
        return;
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap =
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    if (innerPixelMap == nullptr) {
        SLOGE("Invalid innerPixelMap null");
        return;
    }

    std::shared_ptr<AVMediaDescription> mediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        mediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (mediaDescription == nullptr) {
        SLOGE("OnAlbumCoverChanged with nullptr mediaDescription, return with default");
        return;
    }
    mediaDescription->SetIcon(innerPixelMap);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    {
        std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
        for (auto listener : streamPlayerListenerList_) {
            if (listener != nullptr) {
                SLOGI("trigger the OnMediaItemChange for registered listeners on Album change");
                listener->OnMediaItemChange(queueItem);
            }
        }
    }
    {
        std::lock_guard lockGuard(curItemLock_);
        currentAVQueueItem_ = queueItem;
    }
    SLOGI("Received AlbumCoverChanged callback done");
}

void HwCastStreamPlayer::OnAvailableCapabilityChanged(const CastEngine::StreamCapability &streamCapability)
{
    SLOGE("Received OnAvailableCapabilityChanged callback");
    std::vector<int32_t> supportedCastCmds;
    checkCmdsFromAbility(streamCapability, supportedCastCmds);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnValidCommandChange for registered listeners");
            listener->OnValidCommandChange(supportedCastCmds);
        }
    }
}

void HwCastStreamPlayer::OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData)
{
    SLOGD("Stream player received keyRequest event");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnKeyRequest for registered listeners");
            listener->OnKeyRequest(assetId, keyRequestData);
        }
    }
    SLOGI("Stream player received keyRequest event done");
}

void HwCastStreamPlayer::checkCmdsFromAbility(
    const CastEngine::StreamCapability& streamCapability, std::vector<int32_t>& supportedCastCmds)
{
    if (streamCapability.isPlaySupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    }
    if (streamCapability.isPauseSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    }
    if (streamCapability.isStopSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    }
    if (streamCapability.isNextSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    }
    if (streamCapability.isPreviousSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
    }
    if (streamCapability.isSeekSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    }
    if (streamCapability.isFastForwardSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    }
    if (streamCapability.isFastRewindSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    }
    if (streamCapability.isLoopModeSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE);
    }
    if (streamCapability.isSetVolumeSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    }
}

void HwCastStreamPlayer::checkAbilityFromCmds(
    const std::vector<int32_t>& supportedCastCmds, CastEngine::StreamCapability& streamCapability)
{
    for (const int32_t cmd : supportedCastCmds) {
        switch (cmd) {
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY:
                streamCapability.isPlaySupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PAUSE:
                streamCapability.isPauseSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_STOP:
                streamCapability.isStopSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT:
                streamCapability.isNextSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS:
                streamCapability.isPreviousSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
                streamCapability.isSeekSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
                streamCapability.isFastForwardSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
                streamCapability.isFastRewindSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE:
                streamCapability.isLoopModeSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME:
                streamCapability.isSetVolumeSupported = true;
                break;
            default:
                break;
        }
    }
    streamCapability.isToggleFavoriteSupported = false;
}
} // namespace OHOS::AVSession
