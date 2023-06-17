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

namespace OHOS::AVSession {
calss HwCastStreamPlayer : public IAVCastControllerProxy, public CastEngine::IStreamPlayerListener,
    public std::enable_shared_from_this<HwCastStreamPlayer> {
public:
    HwCastStreamPlayer(std::shared_ptr<CastEngine::IStreamPlayer> streamPlayer) : streamPlayer_(streamPlayer) {}
    ~HwCastStreamPlayer() override;
    virtual void Init() override;
    virtual void Release() override;
    virtual void SendControlCommand(const AVCastControlCommand castControlCommand) override;
    virtual int32_t SetMediaList(MediaInfoHolder &mediaInfoHolder) override;
    virtual void UpdateMediaInfo(MediaInfo &mediaInfo) override;  
    virtual int32_t GetDuration(int32_t &duration) override;
    virtual int32_t GetPosition(int32_t &position) override;
    virtual int32_t GetVolume(int32_t &volume) override;
    virtual int32_t GetLoopMode(int32_t &loopMode) override;
    virtual int32_t GetPlaySpeed(int32_t &playSpeed) override;
    virtual int32_t GetPlayState(AVCastPlayerState &playerState) override;
    virtual int32_t SetDisplaySurface(std::string &surfaceId) override;
    virtual int32_t RegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener listener>) override;
    virtual int32_t UnRegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener listener>) override;

    void OnStateChanged(const CastEngine::PlayerStates playbackState, bool isPlayWhenReady) override;
    void OnPositionChanged(int position, int bufferPosition, int duration) override;
    void OnMediaItemChanged(const CastEngine::MediaInfo &mediaInfo) override;
    void OnVolumeChanged(int volume) override;
    void OnLoopModeChanged(const CastEngine::LoopMode loopMode) override;
    void OnPlaySpeedChanged(const CastEngine::PlaybackSpeed speed) override;
    void OnPlayError(int errorCode, const std::string &errorMsg) override;
    void OnVideoSizeChanged(int width, int height) override;

private:
    std::mutex mutex_;
    std::shared_ptr<CastEngine::IStreamPlayer> streamPlayer_;
    std::vector<std::shared_ptr<IAVCastControllerProxyListener>> streamPlayerListenerList_;
    std::map<CastEngine::PlayerStates, std::string> castPlusStateToString_ = {
        {CastEngine::PlayerStates::PLAYER_STATE_ERROR, "error"},
        {CastEngine::PlayerStates::PLAYER_IDLE, "idle"},
        {CastEngine::PlayerStates::PLAYER_STATE_ERROR, "error"},
        {CastEngine::PlayerStates::PLAYER_INITIALIZED, "initialized"},
        {CastEngine::PlayerStates::PLAYER_PREPARING, "preparing"},
        {CastEngine::PlayerStates::PLAYER_PREPARED, "prepared"},
        {CastEngine::PlayerStates::PLAYER_STARTED, "started"},
        {CastEngine::PlayerStates::PLAYER_PAUSED, "paused"},
        {CastEngine::PlayerStates::PLAYER_STOPPED, "stopped"},
        {CastEngine::PlayerStates::PLAYER_PLAYBACK_COMPLETE, "completed"},
        {CastEngine::PlayerStates::PLAYER_RELEASED, "released"}
    };
};
} // namespace OHOS::AVSession

#endif