/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "avmedia_center_control_type.h"

namespace OHOS::AVSession {

const std::unordered_map<int32_t, std::string>& GetMediaCenterTypeToStrMap()
{
    static const std::unordered_map<int32_t, std::string> g_mediaCenterTypeToStr = {
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_NEXT), "playNext"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_PREVIOUS), "playPrevious"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_FAST_FORWARD), "fastForward"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_REWIND), "rewind"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_SPEED), "setSpeed"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_LOOP_MODE), "setLoopMode"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_TOGGLE_FAVORITE), "toggleFavorite"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY), "play"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PAUSE), "pause"}
    };
    return g_mediaCenterTypeToStr;
}

const std::unordered_map<std::string, int32_t>& GetMediaCenterTypeToNumMap()
{
    static const std::unordered_map<std::string, int32_t> g_mediaCenterTypeToNum = {
        {"playNext", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_NEXT)},
        {"playPrevious", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_PREVIOUS)},
        {"fastForward", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_FAST_FORWARD)},
        {"rewind", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_REWIND)},
        {"setSpeed", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_SPEED)},
        {"setLoopMode", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_LOOP_MODE)},
        {"toggleFavorite", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_TOGGLE_FAVORITE)},
        {"play", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY)},
        {"pause", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PAUSE)}
    };
    return g_mediaCenterTypeToNum;
}

} // namespace OHOS::AVSession