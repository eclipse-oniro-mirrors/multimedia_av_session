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

#ifndef OHOS_NAPI_SESSIONLISTENER_CALLBACK_H
#define OHOS_NAPI_SESSIONLISTENER_CALLBACK_H

#include <memory>
#include <map>
#include "avsession_info.h"
#include "avsession_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/avsession_napi_utils.h"
#include "utils/uv_queue.h"

namespace OHOS {
namespace AVSession {
static const std::string SESSIONCREATED_CALLBACK = "sessionCreated";
static const std::string SESSIONRELEASED_CALLBACK = "sessionDestroyed";
static const std::string TOPSESSIONCHANGED_CALLBACK = "topSessionChanged";
static const std::string SESSIONSERVICEDIED_CALLBACK = "sessionServiceDied";

class NapiSessionListenerCallback : public SessionListener,
                                    public std::enable_shared_from_this<NapiSessionListenerCallback> {
public:
    explicit NapiSessionListenerCallback();
    virtual ~NapiSessionListenerCallback();

    void OnSessionCreate(const AVSessionDescriptor& descriptor) override;
    void OnSessionRelease(const AVSessionDescriptor& descriptor) override;
    void OnTopSessionChanged(const AVSessionDescriptor& descriptor) override;
    void OnSessionServiceDied();
    void SaveCallbackReference(const std::string& callbackName, napi_value callback, napi_env env);
    void ReleaseCallbackReference(const std::string& callbackName);
    bool hasCallback(const std::string& callbackName); 

private:
    napi_env env_;
    std::mutex mutex_;
    std::shared_ptr<UvQueue> uvQueue_;
    std::map<std::string, napi_ref> bindCallbackMap = {
        {SESSIONCREATED_CALLBACK, nullptr},
        {SESSIONRELEASED_CALLBACK, nullptr},
        {TOPSESSIONCHANGED_CALLBACK, nullptr},
        {SESSIONSERVICEDIED_CALLBACK, nullptr}
    };
};
} // namespace AVSession
} // namespace OHOS
#endif // OHOS_NAPI_SESSIONLISTENER_CALLBACK_H
