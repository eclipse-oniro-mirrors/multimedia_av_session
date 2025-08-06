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

#ifndef TAIHE_SESSIONLISTENER_H
#define TAIHE_SESSIONLISTENER_H

#include <list>
#include <memory>
#include "avsession_info.h"
#include "avsession_manager.h"
#include "taihe_async_callback.h"
#include "taihe_headers.h"
#include "event_handler.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;
class TaiheSessionListener : public OHOS::AVSession::SessionListener,
                             public std::enable_shared_from_this<TaiheSessionListener> {
public:
    enum {
        EVENT_SESSION_CREATED,
        EVENT_SESSION_DESTROYED,
        EVENT_TOP_SESSION_CHANGED,
        EVENT_AUDIO_SESSION_CHECKED,
        EVENT_DEVICE_AVAILABLE,
        EVENT_DEVICE_LOG_EVENT,
        EVENT_DEVICE_OFFLINE,
        EVENT_DEVICE_STATE_CHANGED,
        EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED,
        EVENT_TYPE_MAX
    };

    TaiheSessionListener();
    ~TaiheSessionListener() override;

    void OnSessionCreate(const OHOS::AVSession::AVSessionDescriptor& descriptor) override;
    void OnSessionRelease(const OHOS::AVSession::AVSessionDescriptor& descriptor) override;
    void OnTopSessionChange(const OHOS::AVSession::AVSessionDescriptor& descriptor) override;
    void OnAudioSessionChecked(const int32_t uid) override;
    void OnDeviceAvailable(const OHOS::AVSession::OutputDeviceInfo& castOutputDeviceInfo) override;
    void OnDeviceLogEvent(const OHOS::AVSession::DeviceLogEventCode eventId, const int64_t param) override;
    void OnDeviceOffline(const std::string& deviceId) override;
    void OnDeviceStateChange(const OHOS::AVSession::DeviceState& deviceState) override;
    void OnRemoteDistributedSessionChange(
        const std::vector<OHOS::sptr<IRemoteObject>>& sessionControllers) override;

    int32_t AddCallback(int32_t event, std::shared_ptr<uintptr_t> ref);
    int32_t RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> ref);

private:
    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;
    void HandleEvent(int32_t event, TaiheFuncExecute callback);

    struct DataContext {
        string deviceId;
        array<AVSessionController> sessionControllers;
    };

    std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    std::mutex lock_;
    std::list<std::shared_ptr<uintptr_t>> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_ = std::make_shared<bool>(false);
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
    DataContext dataContext_ = {};
};
} // namespace ANI::AVSession
#endif // TAIHE_SESSIONLISTENER_H