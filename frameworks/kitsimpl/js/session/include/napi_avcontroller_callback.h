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

#ifndef OHOS_NAPI_AVCONTROLLER_CALLBACK_H
#define OHOS_NAPI_AVCONTROLLER_CALLBACK_H

#include "avsession_info.h"
#include "avsession_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_callback.h"

namespace OHOS::AVSession {
class NapiAVControllerCallback : public AVControllerCallback {
public:
    enum {
        EVENT_SESSION_DESTROY,
        EVENT_PLAYBACK_STATE_CHANGE,
        EVENT_META_DATA_CHANGE,
        EVENT_ACTIVE_STATE_CHANGE,
        EVENT_VALID_COMMAND_CHANGE,
        EVENT_TYPE_MAX
    };

    NapiAVControllerCallback();
    ~NapiAVControllerCallback() override;

    void OnSessionDestroy() override;
    void OnPlaybackStateChange(const AVPlaybackState& state) override;
    void OnMetaDataChange(const AVMetaData& data) override;
    void OnActiveStateChange(bool isActive) override;
    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;

    napi_status AddCallback(napi_env env, int32_t event, napi_value callback);
    napi_status RemoveCallback(napi_env env, int32_t event);

private:
    std::mutex lock_;
    std::shared_ptr<NapiAsyncCallback> asyncCallback_;
    napi_ref callbacks_[EVENT_TYPE_MAX] {};
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCONTROLLER_CALLBACK_H