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

#include "OHAVSessionCallbackImpl.h"
#include "avcast_control_command.h"

namespace OHOS::AVSession {
OHAVSessionCallbackImpl::~OHAVSessionCallbackImpl()
{
}

void OHAVSessionCallbackImpl::OnPlay()
{
    for (auto it = playCallbacks_.begin(); it != playCallbacks_.end(); ++it) {
        it->first(avsession_, CONTROL_CMD_PLAY, it->second);
    }
}

void OHAVSessionCallbackImpl::OnPause()
{
    for (auto it = pauseCallbacks_.begin(); it != pauseCallbacks_.end(); ++it) {
        it->first(avsession_, CONTROL_CMD_PAUSE, it->second);
    }
}

void OHAVSessionCallbackImpl::OnStop()
{
    for (auto it = stopCallbacks_.begin(); it != stopCallbacks_.end(); ++it) {
        it->first(avsession_, CONTROL_CMD_STOP, it->second);
    }
}

void OHAVSessionCallbackImpl::OnPlayNext()
{
    for (auto it = playNextCallbacks_.begin(); it != playNextCallbacks_.end(); ++it) {
        it->first(avsession_, CONTROL_CMD_PLAY_NEXT, it->second);
    }
}

void OHAVSessionCallbackImpl::OnPlayPrevious()
{
    for (auto it = playPreviousCallbacks_.begin(); it != playPreviousCallbacks_.end(); ++it) {
        it->first(avsession_, CONTROL_CMD_PLAY_PREVIOUS, it->second);
    }
}

void OHAVSessionCallbackImpl::OnFastForward(int64_t time)
{
    for (auto it = forwardCallbacks_.begin(); it != forwardCallbacks_.end(); ++it) {
        it->first(avsession_, time, it->second);
    }
}

void OHAVSessionCallbackImpl::OnRewind(int64_t time)
{
    for (auto it = rewindCallbacks_.begin(); it != rewindCallbacks_.end(); ++it) {
        it->first(avsession_, time, it->second);
    }
}

void OHAVSessionCallbackImpl::OnSeek(int64_t time)
{
    for (auto it = seekCallbacks_.begin(); it != seekCallbacks_.end(); ++it) {
        it->first(avsession_, time, it->second);
    }
}

void OHAVSessionCallbackImpl::OnSetSpeed(double speed)
{
    for (auto it = setSpeedCallbacks_.begin(); it != setSpeedCallbacks_.end(); ++it) {
        it->first(avsession_, speed, it->second);
    }
}

void OHAVSessionCallbackImpl::OnSetLoopMode(int32_t loopMode)
{
    for (auto it = setLoopModeCallbacks_.begin(); it != setLoopModeCallbacks_.end(); ++it) {
        it->first(avsession_, static_cast<AVSession_LoopMode>(loopMode), it->second);
    }
}

void OHAVSessionCallbackImpl::OnToggleFavorite(const std::string& mediald)
{
    for (auto it = toggleFavoriteCallbacks_.begin(); it != toggleFavoriteCallbacks_.end(); ++it) {
        it->first(avsession_, mediald.c_str(), it->second);
    }
}

void OHAVSessionCallbackImpl::OnPlayFromAssetId(int64_t assetId)
{
    std::string str = std::to_string(assetId);
    for (auto it = playFromAssetIdCallbacks_.begin(); it != playFromAssetIdCallbacks_.end(); ++it) {
        it->first(avsession_, str.c_str(), it->second);
    }
}

AVSession_ErrCode OHAVSessionCallbackImpl::SetPlayCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (playCallbacks_.begin(), playCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    if (it != playCallbacks_.end()) {
        playCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::SetPauseCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (pauseCallbacks_.begin(), pauseCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    if (it != pauseCallbacks_.end()) {
        pauseCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::SetStopCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (stopCallbacks_.begin(), stopCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    if (it != stopCallbacks_.end()) {
        stopCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::SetPlayNextCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (playNextCallbacks_.begin(), playNextCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    if (it != playNextCallbacks_.end()) {
        playNextCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::SetPlayPreviousCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (playPreviousCallbacks_.begin(), playPreviousCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    if (it != playPreviousCallbacks_.end()) {
        playPreviousCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnSetPlayCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    std::remove_if (playCallbacks_.begin(), playCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnSetPauseCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    std::remove_if (pauseCallbacks_.begin(), pauseCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnSetStopCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    std::remove_if (stopCallbacks_.begin(), stopCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnSetPlayNextCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    std::remove_if (playNextCallbacks_.begin(), playNextCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnSetPlayPreviousCallback(OH_AVSession* avsession,
    AVSession_ControlCommand command, OH_AVSessionCallback_OnCommand callback)
{
    std::remove_if (playPreviousCallbacks_.begin(), playPreviousCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnCommand, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (forwardCallbacks_.begin(), forwardCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnFastForward, void*> &element) {
            return element.first == callback;
        });
    if (it != forwardCallbacks_.end()) {
        forwardCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterForwardCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback)
{
    std::remove_if (forwardCallbacks_.begin(), forwardCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnFastForward, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (rewindCallbacks_.begin(), rewindCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnFastForward, void*> &element) {
            return element.first == callback;
        });
    if (it != rewindCallbacks_.end()) {
        rewindCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterRewindCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnFastForward callback)
{
    std::remove_if (rewindCallbacks_.begin(), rewindCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnFastForward, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (seekCallbacks_.begin(), seekCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSeek, void*> &element) {
            return element.first == callback;
        });
    if (it != seekCallbacks_.end()) {
        seekCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterSeekCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSeek callback)
{
    std::remove_if (seekCallbacks_.begin(), seekCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSeek, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterSpeedCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetSpeed callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (setSpeedCallbacks_.begin(), setSpeedCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSetSpeed, void*> &element) {
            return element.first == callback;
        });
    if (it != setSpeedCallbacks_.end()) {
        setSpeedCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterSpeedCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetSpeed callback)
{
    std::remove_if (setSpeedCallbacks_.begin(), setSpeedCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSetSpeed, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback, void*userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (setLoopModeCallbacks_.begin(), setLoopModeCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSetLoopMode, void*> &element) {
            return element.first == callback;
        });
    if (it != setLoopModeCallbacks_.end()) {
        setLoopModeCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterSetLoopModeCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnSetLoopMode callback)
{
    std::remove_if (setLoopModeCallbacks_.begin(), setLoopModeCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnSetLoopMode, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback, void* userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (toggleFavoriteCallbacks_.begin(), toggleFavoriteCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnToggleFavorite, void*> &element) {
            return element.first == callback;
        });
    if (it != toggleFavoriteCallbacks_.end()) {
        toggleFavoriteCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterToggleFavoriteCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnToggleFavorite callback)
{
    std::remove_if (toggleFavoriteCallbacks_.begin(), toggleFavoriteCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnToggleFavorite, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::RegisterPlayFromAssetIdCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnPlayFromAssetId callback, void* userData)
{
    if (avsession_ == nullptr) {
        avsession_ = avsession;
    }
    auto it = std::find_if (playFromAssetIdCallbacks_.begin(), playFromAssetIdCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnPlayFromAssetId, void*> &element) {
            return element.first == callback;
        });
    if (it != playFromAssetIdCallbacks_.end()) {
        playFromAssetIdCallbacks_.emplace_back(std::make_pair(callback, userData));
    }
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OHAVSessionCallbackImpl::UnRegisterPlayFromAssetIdCallback(OH_AVSession* avsession,
    OH_AVSessionCallback_OnPlayFromAssetId callback)
{
    std::remove_if (playFromAssetIdCallbacks_.begin(), playFromAssetIdCallbacks_.end(),
        [callback](const std::pair<OH_AVSessionCallback_OnPlayFromAssetId, void*> &element) {
            return element.first == callback;
        });
    return AV_SESSION_ERR_SUCCESS;
}
}