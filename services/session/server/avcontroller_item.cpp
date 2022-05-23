/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "avcontroller_item.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_item.h"

namespace OHOS::AVSession {
AVControllerItem::AVControllerItem(pid_t pid, sptr<AVSessionItem> &session)
    : pid_(pid), session_(session)
{
    SLOGD("construct");
}

AVControllerItem::~AVControllerItem()
{
    SLOGD("destroy");
}

int32_t AVControllerItem::RegisterCallbackInner(const sptr<IAVControllerCallback> &callback)
{
    callback_ = callback;
    return 0;
}

int32_t AVControllerItem::GetAVPlaybackState(AVPlaybackState &state)
{
    return 0;
}

int32_t AVControllerItem::GetAVMetaData(AVMetaData &data)
{
    return 0;
}

int32_t AVControllerItem::GetAVVolumeInfo(AVVolumeInfo &info)
{
    return 0;
}

int32_t AVControllerItem::SendSystemMediaKeyEvent(MMI::KeyEvent& keyEvent)
{
    return 0;
}

int32_t AVControllerItem::GetLaunchAbility(AbilityRuntime::WantAgent::WantAgent &ability)
{
    return 0;
}

int32_t AVControllerItem::GetSupportedCommand(std::vector<int32_t> &cmds)
{
    return 0;
}

int32_t AVControllerItem::IsSessionActive(bool &isActive)
{
    return 0;
}

int32_t AVControllerItem::SendCommand(AVControlCommand &cmd)
{
    return 0;
}

int32_t AVControllerItem::SetMetaFilter(const AVMetaData::MetaMaskType &filter)
{
    metaMask_ = filter;
    return AVSESSION_SUCCESS;
}

int32_t AVControllerItem::Release()
{
    callback_ = nullptr;
    return AVSESSION_SUCCESS;
}

void AVControllerItem::HandleSessionRelease(const AVSessionDescriptor &descriptor)
{
    callback_->OnSessionRelease(descriptor);
}

void AVControllerItem::HandlePlaybackStateChange(const AVPlaybackState &state)
{
    callback_->OnPlaybackStateUpdate(state);
}

void AVControllerItem::HandleMetaDataChange(const AVMetaData &data)
{
    callback_->OnMetaDataUpdate(data);
}

void AVControllerItem::HandleVolumeInfoChange(const AVVolumeInfo &info)
{
    callback_->OnVolumeInfoChange(info);
}

pid_t AVControllerItem::GetPid()
{
    return pid_;
}

void AVControllerItem::ClearSession()
{
    session_ = nullptr;
}
} // OHOS::AVSession