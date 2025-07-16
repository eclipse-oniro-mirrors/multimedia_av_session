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

#ifndef TAIHE_PLAYBACK_STATE_H
#define TAIHE_PLAYBACK_STATE_H

#include <map>
#include <string>
#include <vector>

#include "avplayback_state.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaihePlaybackState {
public:
    static int32_t ConvertFilter(string_view filter, OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType &mask);
    static int32_t ConvertFilter(array<string> filter, OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType &mask);

    static int32_t GetAVPlaybackState(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetAVPlaybackState(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);
    static AVPlaybackState CreateUndefinedAVPlaybackState();

    using GetterType = std::function<int32_t(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out)>;

private:
    static int32_t GetState(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetState(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetSpeed(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetSpeed(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetPosition(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetPosition(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetBufferedTime(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetBufferedTime(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetLoopMode(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetLoopMode(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetIsFavorite(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetIsFavorite(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetActiveItemId(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetActiveItemId(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetVolume(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetVolume(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetMaxVolume(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetMaxVolume(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetMuted(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetMuted(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetDuration(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetDuration(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetVideoWidth(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetVideoWidth(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetVideoHeight(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetVideoHeight(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static int32_t GetExtras(AVPlaybackState const &in, OHOS::AVSession::AVPlaybackState &out);
    static int32_t SetExtras(const OHOS::AVSession::AVPlaybackState &in, AVPlaybackState &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::map<std::string, int32_t> filterMap_;
};
} // namespace ANI::AVSession
#endif // TAIHE_PLAYBACK_STATE_H