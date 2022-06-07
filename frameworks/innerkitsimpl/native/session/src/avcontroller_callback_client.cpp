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

#include "avcontroller_callback_client.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControllerCallbackClient::AVControllerCallbackClient(const std::shared_ptr<AVControllerCallback>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void AVControllerCallbackClient::OnSessionRelease(const AVSessionDescriptor &descriptor)
{
    if (callback_) {
        callback_->OnSessionRelease(descriptor);
    }
}

void AVControllerCallbackClient::OnPlaybackStateUpdate(const AVPlaybackState &state)
{
    if (callback_) {
        callback_->OnPlaybackStateUpdate(state);
    }
}

void AVControllerCallbackClient::OnMetaDataUpdate(const AVMetaData &data)
{
    if (callback_) {
        callback_->OnMetaDataUpdate(data);
    }
}

void AVControllerCallbackClient::OnActiveStateChange(bool isActive)
{
    if (callback_) {
        callback_->OnActiveStateChange(isActive);
    }
}
}