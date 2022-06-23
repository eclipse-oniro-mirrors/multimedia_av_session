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

#ifndef OHOS_NAPI_AVSESSION_CONTROLLER_H
#define OHOS_NAPI_AVSESSION_CONTROLLER_H

#include "avsession_controller.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_avcontroller_callback.h"

namespace OHOS::AVSession {
class NapiAVSessionController {
public:
    NapiAVSessionController();
    ~NapiAVSessionController();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, std::shared_ptr<AVSessionController>& nativeController,
                                   napi_value& out);

    using OnEventHandlerType = std::function<napi_status(napi_env, NapiAVSessionController*, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, NapiAVSessionController*)>;

private:
    static napi_value ConstructorCallback(napi_env env, napi_callback_info info);
    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_status OnSessionDestroy(napi_env env, NapiAVSessionController* napiController, napi_value callback);

    static napi_status OffSessionDestroy(napi_env env, NapiAVSessionController* napiController);

    napi_ref wrapperRef_ {};
    int32_t sessionId_ = -1;
    std::shared_ptr<AVSessionController> controller_;
    std::shared_ptr<NapiAVControllerCallback> callback_;

    static std::map<std::string, OnEventHandlerType> onEventHandlers_;
    static std::map<std::string, OffEventHandlerType> offEventHandlers_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_CONTROLLER_H