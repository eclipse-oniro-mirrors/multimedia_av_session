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

#ifndef TAIHE_AVCONTROLLER_CALLBACK_H
#define TAIHE_AVCONTROLLER_CALLBACK_H

#include <list>
#include <thread>

#include "avsession_info.h"
#include "taihe_work.h"
#include "taihe_async_callback.h"
#include "event_handler.h"
#include "taihe_utils.h"
#include "taihe_avsession_enum.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVControllerCallback : public OHOS::AVSession::AVControllerCallback,
    public std::enable_shared_from_this<TaiheAVControllerCallback> {
public:
    enum {
        EVENT_SESSION_DESTROY,
        EVENT_PLAYBACK_STATE_CHANGE,
        EVENT_META_DATA_CHANGE,
        EVENT_ACTIVE_STATE_CHANGE,
        EVENT_VALID_COMMAND_CHANGE,
        EVENT_OUTPUT_DEVICE_CHANGE,
        EVENT_SESSION_EVENT_CHANGE,
        EVENT_QUEUE_ITEMS_CHANGE,
        EVENT_QUEUE_TITLE_CHANGE,
        EVENT_EXTRAS_CHANGE,
        EVENT_CUSTOM_DATA_CHANGE,
        EVENT_AVCALL_META_DATA_CHANGE,
        EVENT_AVCALL_STATE_CHANGE,
        EVENT_TYPE_MAX,
    };

    TaiheAVControllerCallback(ani_env *env);
    ~TaiheAVControllerCallback() override;

    void OnAVCallMetaDataChange(const OHOS::AVSession::AVCallMetaData &avCallMetaData) override;
    void OnAVCallStateChange(const OHOS::AVSession::AVCallState &avCallState) override;
    void OnSessionDestroy() override;
    void OnPlaybackStateChange(const OHOS::AVSession::AVPlaybackState &state) override;
    void OnMetaDataChange(const OHOS::AVSession::AVMetaData &data) override;
    void OnActiveStateChange(bool isActive) override;
    void OnValidCommandChange(const std::vector<int32_t> &cmds) override;
    void OnOutputDeviceChange(const int32_t connectionState, const OHOS::AVSession::OutputDeviceInfo &info) override;
    void OnSessionEventChange(const std::string &event, const OHOS::AAFwk::WantParams &args) override;
    void OnQueueItemsChange(const std::vector<OHOS::AVSession::AVQueueItem> &items) override;
    void OnQueueTitleChange(const std::string &title) override;
    void OnExtrasChange(const OHOS::AAFwk::WantParams &extras) override;
    void OnCustomData(const OHOS::AAFwk::WantParams &customData) override;

    int32_t AddCallback(int32_t event, std::shared_ptr<uintptr_t> callback);
    int32_t RemoveCallback(int32_t event, std::shared_ptr<uintptr_t> callback);
    void AddCallbackForSessionDestroy(const std::function<void(void)> &sessionDestroyCallback);

private:
    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;

    void HandleEventWithThreadSafe(int32_t event, int32_t state, TaiheFuncExecute callback);

    void HandleEvent(int32_t event, TaiheFuncExecute callback);

    void CallWithThreadSafe(std::shared_ptr<uintptr_t> method, std::shared_ptr<bool> isValid, int state,
        const std::function<bool()>& checkCallbackValid, TaiheFuncExecute execute = TaiheFuncExecute());

    struct DataContextForThreadSafe {
        std::shared_ptr<uintptr_t> method;
        int state;
        std::shared_ptr<bool> isValid;
        TaiheFuncExecute execute;
        std::function<bool()> checkCallbackValid;
    };

    struct DataContextForTaihe {
        array<string> cmds;
        string sessionEvent;
        array<AVQueueItem> queueItems;
        string queueTitle;
    };

    static void ThreadSafeCallback(ani_env *env, DataContextForThreadSafe *data);

    ani_env *env_ = nullptr;
    static std::mutex sWorkerMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
    std::mutex lock_;
    std::shared_ptr<TaiheAsyncCallback> asyncCallback_;
    std::list<std::shared_ptr<uintptr_t>> callbacks_[EVENT_TYPE_MAX] {};
    std::shared_ptr<bool> isValid_;
    std::function<void(void)> sessionDestroyCallback_;
    DataContextForTaihe dataContext_ {};
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCONTROLLER_CALLBACK_H