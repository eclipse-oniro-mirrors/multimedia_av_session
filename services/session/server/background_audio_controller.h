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
#include "background_task_mgr_helper.h"
#include "continuous_task_callback_info.h"

namespace OHOS::AVSession {
class AVSessionService;
class BackgroundAudioController : public SessionListener {
public:
    using BackgroundMode = AppExecFwk::BackgroundMode;
    using StreamUsage = AudioStandard::StreamUsage;
    using ContinuousTaskCallbackInfo = BackgroundTaskMgr::ContinuousTaskCallbackInfo;

    BackgroundAudioController();
    ~BackgroundAudioController() override;

    void OnSessionCreate(const AVSessionDescriptor& descriptor) override;
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override;
    void OnTopSessionChange(const AVSessionDescriptor& descriptor) override {}
    void OnAudioSessionChecked(const int32_t uid) override {}
    void OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override {};

    void Init(AVSessionService *ptr);

    void HandleAudioStreamRendererStateChange(const AudioRendererChangeInfos& infos);
    void HandleAppMuteState(int32_t uid, int32_t pid, bool isBackground);
    void RendererChangeReport(AudioStandard::AudioRendererChangeInfo& info);

private:
    bool HasAVSession(int32_t uid);
    bool IsBackgroundMode(int32_t creatorUid, BackgroundMode backgroundMode) const;

    std::recursive_mutex lock_;
    std::map<int32_t, std::set<int32_t>> sessionUIDs_;
    AVSessionService *ptr_;
};
}
#endif // AV_SESSION_BACKGROUND_AUDIO_CONTROLLER_H
