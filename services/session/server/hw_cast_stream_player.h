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

#ifndef HW_CAST_STREAM_PLAYER_H
#define HW_CAST_STREAM_PLAYER_H

#include <mutex>

#include "cast_engine_common.h"
#include "i_stream_player.h"
#include "i_avcast_controller_proxy.h"
#include "avsession_pixel_map_adapter.h"

namespace OHOS::AVSession {
class HwCastStreamPlayer : public IAVCastControllerProxy, public CastEngine::IStreamPlayerListener,
    public std::enable_shared_from_this<HwCastStreamPlayer> {
public:
    explicit HwCastStreamPlayer(std::shared_ptr<CastEngine::IStreamPlayer> streamPlayer)
        : streamPlayer_(streamPlayer) {}
    ~HwCastStreamPlayer() override;
    void Init();
    void Release() override;
    void SendControlCommand(const AVCastControlCommand castControlCommand) override;
    AVQueueItem GetCurrentItem() override;
    int32_t Start(const AVQueueItem& avQueueItem) override;
    int32_t Prepare(const AVQueueItem& avQueueItem) override;
    int32_t GetDuration(int32_t &duration) override;
    int32_t GetCastAVPlaybackState(AVPlaybackState& avPlaybackState) override;
    int32_t SetDisplaySurface(std::string &surfaceId) override;
    int32_t RegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>) override;
    int32_t UnRegisterControllerListener(const std::shared_ptr<IAVCastControllerProxyListener>) override;

    void OnStateChanged(const CastEngine::PlayerStates playbackState, bool isPlayWhenReady) override;
    void OnPositionChanged(int position, int bufferPosition, int duration) override;
    void OnMediaItemChanged(const CastEngine::MediaInfo &mediaInfo) override;
    void OnVolumeChanged(int volume, int maxVolume) override;
    void OnLoopModeChanged(const CastEngine::LoopMode loopMode) override;
    void OnNextRequest() override;
    void OnPreviousRequest() override;
    void OnPlaySpeedChanged(const CastEngine::PlaybackSpeed speed) override;
    void OnPlayerError(int errorCode, const std::string &errorMsg) override;
    void OnSeekDone(int32_t seekNumber) override;
    void OnVideoSizeChanged(int width, int height) override;
    void OnEndOfStream(int isLooping) override;
    void OnPlayRequest(const CastEngine::MediaInfo &mediaInfo) override;
    void OnImageChanged(std::shared_ptr<Media::PixelMap> pixelMap) override;
    void OnAlbumCoverChanged(std::shared_ptr<Media::PixelMap> pixelMap) override;

    void SendControlCommandWithParams(const AVCastControlCommand castControlCommand);

private:
    std::recursive_mutex streamPlayerLock_;
    std::shared_ptr<CastEngine::IStreamPlayer> streamPlayer_;
    std::vector<std::shared_ptr<IAVCastControllerProxyListener>> streamPlayerListenerList_;
    AVQueueItem currentAVQueueItem_;
    std::map<CastEngine::PlayerStates, int32_t> castPlusStateToString_ = {
        {CastEngine::PlayerStates::PLAYER_STATE_ERROR, AVPlaybackState::PLAYBACK_STATE_ERROR},
        {CastEngine::PlayerStates::PLAYER_IDLE, AVPlaybackState::PLAYBACK_STATE_INITIAL},
        {CastEngine::PlayerStates::PLAYER_INITIALIZED, AVPlaybackState::PLAYBACK_STATE_INITIAL},
        {CastEngine::PlayerStates::PLAYER_PREPARING, AVPlaybackState::PLAYBACK_STATE_PREPARE},
        {CastEngine::PlayerStates::PLAYER_PREPARED, AVPlaybackState::PLAYBACK_STATE_PREPARE},
        {CastEngine::PlayerStates::PLAYER_STARTED, AVPlaybackState::PLAYBACK_STATE_PLAY},
        {CastEngine::PlayerStates::PLAYER_PAUSED, AVPlaybackState::PLAYBACK_STATE_PAUSE},
        {CastEngine::PlayerStates::PLAYER_STOPPED, AVPlaybackState::PLAYBACK_STATE_STOP},
        {CastEngine::PlayerStates::PLAYER_PLAYBACK_COMPLETE, AVPlaybackState::PLAYBACK_STATE_COMPLETED},
        {CastEngine::PlayerStates::PLAYER_RELEASED, AVPlaybackState::PLAYBACK_STATE_RELEASED},
        {CastEngine::PlayerStates::PLAYER_BUFFERING, AVPlaybackState::PLAYBACK_STATE_BUFFERING}
    };
    std::map<CastEngine::PlaybackSpeed, double> castPlusSpeedToDouble_ = {
        {CastEngine::PlaybackSpeed::SPEED_FORWARD_0_75_X, 0.75},
        {CastEngine::PlaybackSpeed::SPEED_FORWARD_1_00_X, 1.00},
        {CastEngine::PlaybackSpeed::SPEED_FORWARD_1_25_X, 1.25},
        {CastEngine::PlaybackSpeed::SPEED_FORWARD_1_75_X, 1.75},
        {CastEngine::PlaybackSpeed::SPEED_FORWARD_2_00_X, 2.00},
    };
    std::map<CastEngine::LoopMode, int32_t> castPlusLoopModeToInt_ = {
        {CastEngine::LoopMode::LOOP_MODE_SEQUENCE, AVPlaybackState::LOOP_MODE_SEQUENCE},
        {CastEngine::LoopMode::LOOP_MODE_SINGLE, AVPlaybackState::LOOP_MODE_SINGLE},
        {CastEngine::LoopMode::LOOP_MODE_LIST, AVPlaybackState::LOOP_MODE_LIST},
        {CastEngine::LoopMode::LOOP_MODE_SHUFFLE, AVPlaybackState::LOOP_MODE_SHUFFLE},
    };
    std::map<int32_t, CastEngine::LoopMode> intLoopModeToCastPlus_ = {
        {AVPlaybackState::LOOP_MODE_SEQUENCE, CastEngine::LoopMode::LOOP_MODE_SEQUENCE},
        {AVPlaybackState::LOOP_MODE_SINGLE, CastEngine::LoopMode::LOOP_MODE_SINGLE},
        {AVPlaybackState::LOOP_MODE_LIST, CastEngine::LoopMode::LOOP_MODE_LIST},
        {AVPlaybackState::LOOP_MODE_SHUFFLE, CastEngine::LoopMode::LOOP_MODE_SHUFFLE},
    };
};
} // namespace OHOS::AVSession

#endif