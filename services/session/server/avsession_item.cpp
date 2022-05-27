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

#include "avsession_item.h"
#include "avsession_service.h"
#include "avcontroller_item.h"
#include "avsession_log.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor)
    : descriptor_()
{
    SLOGD("constructor id=%{public}d", descriptor_.sessionId_);
}

AVSessionItem::~AVSessionItem()
{
    SLOGD("destroy id=%{public}d", descriptor_.sessionId_);
}

int32_t AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

int32_t AVSessionItem::RegisterCallbackInner(sptr<IRemoteObject> &callback)
{
    return 0;
}

int32_t AVSessionItem::Release()
{
    SLOGD("enter");
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleSessionRelease(descriptor_);
    }
    if (serviceCallback_) {
        serviceCallback_(*this);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    return 0;
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    return 0;
}

int32_t AVSessionItem::GetAVPlaybackState(AVPlaybackState& state)
{
    return 0;
}

int32_t AVSessionItem::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    return 0;
}

std::shared_ptr<AVSessionController> AVSessionItem::GetController()
{
    return nullptr;
}

int32_t AVSessionItem::RegisterCallback(std::shared_ptr<AVSessionCallback>& callback)
{
    return 0;
}

int32_t AVSessionItem::Active()
{
    return 0;
}

int32_t AVSessionItem::Disactive()
{
    return 0;
}

bool AVSessionItem::IsActive()
{
    return false;
}

int32_t AVSessionItem::AddSupportCommand(const std::string& cmd)
{
    return 0;
}

AVSessionDescriptor AVSessionItem::GetDescriptor()
{
    return descriptor_;
}

AVPlaybackState AVSessionItem::GetPlaybackState()
{
    return playbackState_;
}

AVMetaData AVSessionItem::GetMetaData()
{
    return metaData_;
}

std::vector<std::string> AVSessionItem::GetSupportCommand()
{
    return supportedCmd_;
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

void AVSessionItem::HandleMediaButtonEvent(const MMI::KeyEvent& keyEvent)
{
    if (callback_ != nullptr) {
        callback_->OnMediaKeyEvent(keyEvent);
    }
}

void AVSessionItem::ExecuteControllerCommand(const AVControlCommand& cmd)
{
}

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& contoller)
{
    return 0;
}

int32_t AVSessionItem::RemoveController(pid_t pid)
{
    return 0;
}

int32_t AVSessionItem::RegisterCallbackForRemote(std::shared_ptr<AVSessionCallback>& callback)
{
    return 0;
}

int32_t AVSessionItem::UnRegisterCallbackForRemote()
{
    return 0;
}

void AVSessionItem::SetPid(pid_t pid)
{
    pid_ = pid;
}

void AVSessionItem::SetUid(uid_t uid)
{
    uid_ = uid;
}

pid_t AVSessionItem::GetPid() const
{
    return pid_;
}

uid_t  AVSessionItem::GetUid()
{
    return uid_;
}

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem &)> &callback)
{
    serviceCallback_ = callback;
}
} // namespace OHOS::AVSession