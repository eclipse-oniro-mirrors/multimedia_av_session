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

#ifndef OHOS_AVMEDIA_CENTER_CONTROL_TYPE_H
#define OHOS_AVMEDIA_CENTER_CONTROL_TYPE_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace OHOS::AVSession {

enum class AVMediaCenterControlType : int32_t {
    MEDIA_CENTER_CTRL_PLAY_NEXT = 0,
    MEDIA_CENTER_CTRL_PLAY_PREVIOUS = 1,
    MEDIA_CENTER_CTRL_FAST_FORWARD = 2,
    MEDIA_CENTER_CTRL_REWIND = 3,
    MEDIA_CENTER_CTRL_SET_SPEED = 4,
    MEDIA_CENTER_CTRL_SET_LOOP_MODE = 5,
    MEDIA_CENTER_CTRL_TOGGLE_FAVORITE = 6,
    MEDIA_CENTER_CTRL_MAX = 7
};

inline const std::unordered_map<int32_t, std::string>& GetMediaCenterTypeToStrMap()
{
    static const std::unordered_map<int32_t, std::string> g_mediaCenterTypeToStr = {
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_NEXT), "playNext"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_PREVIOUS), "playPrevious"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_FAST_FORWARD), "fastForward"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_REWIND), "rewind"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_SPEED), "setSpeed"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_LOOP_MODE), "setLoopMode"},
        {static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_TOGGLE_FAVORITE), "toggleFavorite"}
    };
    return g_mediaCenterTypeToStr;
}

inline const std::unordered_map<std::string, int32_t>& GetMediaCenterTypeToNumMap()
{
    static const std::unordered_map<std::string, int32_t> g_mediaCenterTypeToNum = {
        {"playNext", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_NEXT)},
        {"playPrevious", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_PLAY_PREVIOUS)},
        {"fastForward", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_FAST_FORWARD)},
        {"rewind", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_REWIND)},
        {"setSpeed", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_SPEED)},
        {"setLoopMode", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_SET_LOOP_MODE)},
        {"toggleFavorite", static_cast<int32_t>(AVMediaCenterControlType::MEDIA_CENTER_CTRL_TOGGLE_FAVORITE)}
    };
    return g_mediaCenterTypeToNum;
}

inline std::vector<int32_t> MediaCenterTypesToNums(const std::vector<std::string>& types)
{
    std::vector<int32_t> nums;
    nums.reserve(types.size());
    const auto& typeMap = GetMediaCenterTypeToNumMap();
    for (const auto& type : types) {
        auto iter = typeMap.find(type);
        if (iter != typeMap.end()) {
            nums.push_back(iter->second);
        }
    }
    return nums;
}

inline std::vector<std::string> MediaCenterTypesToStrs(const std::vector<int32_t>& nums)
{
    std::vector<std::string> types;
    types.reserve(nums.size());
    const auto& strMap = GetMediaCenterTypeToStrMap();
    for (int32_t num : nums) {
        auto iter = strMap.find(num);
        if (iter != strMap.end()) {
            types.push_back(iter->second);
        }
    }
    return types;
}

inline bool IsValidMediaCenterControlTypeStr(const std::string& type)
{
    const auto& typeMap = GetMediaCenterTypeToNumMap();
    return typeMap.find(type) != typeMap.end();
}

inline bool IsValidMediaCenterControlTypeNum(int32_t num)
{
    const auto& strMap = GetMediaCenterTypeToStrMap();
    return strMap.find(num) != strMap.end();
}

} // namespace OHOS::AVSession

#endif // OHOS_AVMEDIA_CENTER_CONTROL_TYPE_H
