/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AV_SESSION_BACKGROUND_AUDIO_CONTROLLER_H
#define AV_SESSION_BACKGROUND_AUDIO_CONTROLLER_H

#include <mutex>
#include <set>
#include "avsession_info.h"
#include "audio_adapter.h"
#include "app_manager_adapter.h"

namespace OHOS::AVSession {
class BackgroundAudioController : public SessionListener {
public:
    BackgroundAudioController();
    ~BackgroundAudioController() override;

    void OnSessionCreate(const AVSessionDescriptor &descriptor) override;
    void OnSessionRelease(const AVSessionDescriptor &descriptor) override;
    void OnTopSessionChanged(const AVSessionDescriptor &descriptor) override {}

    void Init();

    void HandleAudioStreamRendererStateChange(const AudioRendererChangeInfos& infos);
    void HandleAppBackgroundState(int32_t uid) const;

private:
    std::recursive_mutex lock_;
    std::set<int32_t> sessionUIDs_;
};
}
#endif // AV_SESSION_BACKGROUND_AUDIO_CONTROLLER_H