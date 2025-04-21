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

#include <mutex>
#include "avsession_controller.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_avcontroller_callback.h"
#include "napi_async_work.h"

namespace OHOS::AVSession {
class NapiAVSessionController {
public:
    NapiAVSessionController();
    ~NapiAVSessionController();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, const std::shared_ptr<AVSessionController>& nativeController,
        napi_value& out);
    static napi_status RepeatedInstance(napi_env env, const std::string& controllerId, napi_value& out);

    using OnEventHandlerType = std::function<napi_status(napi_env, NapiAVSessionController*, napi_value, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, NapiAVSessionController*, napi_value)>;

private:
    static napi_value ConstructorCallback(napi_env env, napi_callback_info info);
    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_value GetAVCallState(napi_env env, napi_callback_info info);
    static napi_value GetAVCallMetaData(napi_env env, napi_callback_info info);
    static napi_value GetAVPlaybackState(napi_env env, napi_callback_info info);
    static napi_value GetAVPlaybackStateSync(napi_env env, napi_callback_info info);
    static napi_value GetAVMetaData(napi_env env, napi_callback_info info);
    static napi_value GetAVMetaDataSync(napi_env env, napi_callback_info info);
    static napi_value SendAVKeyEvent(napi_env env, napi_callback_info info);
    static napi_value GetLaunchAbility(napi_env env, napi_callback_info info);
    static napi_value GetValidCommands(napi_env env, napi_callback_info info);
    static napi_value GetValidCommandsSync(napi_env env, napi_callback_info info);
    static napi_value IsSessionActive(napi_env env, napi_callback_info info);
    static napi_value IsSessionActiveSync(napi_env env, napi_callback_info info);
    static napi_value SendControlCommand(napi_env env, napi_callback_info info);
    static napi_value SendCommonCommand(napi_env env, napi_callback_info info);
    static napi_value Destroy(napi_env env, napi_callback_info info);
    static napi_value GetRealPlaybackPositionSync(napi_env env, napi_callback_info info);
    static napi_value GetOutputDevice(napi_env env, napi_callback_info info);
    static napi_value GetOutputDeviceSync(napi_env env, napi_callback_info info);
    static napi_value GetAVQueueItems(napi_env env, napi_callback_info info);
    static napi_value GetAVQueueItemsSync(napi_env env, napi_callback_info info);
    static napi_value GetAVQueueTitle(napi_env env, napi_callback_info info);
    static napi_value GetAVQueueTitleSync(napi_env env, napi_callback_info info);
    static napi_value SkipToQueueItem(napi_env env, napi_callback_info info);
    static napi_value GetExtras(napi_env env, napi_callback_info info);
    static napi_value GetExtrasWithEvent(napi_env env, napi_callback_info info);

    static napi_status OnAVCallMetaDataChange(napi_env env, NapiAVSessionController* napiController,
        napi_value param, napi_value callback);
    static napi_status OnAVCallStateChange(napi_env env, NapiAVSessionController* napiController,
        napi_value param, napi_value callback);
    static napi_status OnSessionDestroy(napi_env env, NapiAVSessionController* napiController,
                                        napi_value param, napi_value callback);
    static napi_status OnPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
                                             napi_value param, napi_value callback);
    static napi_status OnMetaDataChange(napi_env env, NapiAVSessionController* napiController,
                                        napi_value param, napi_value callback);
    static napi_status OnActiveStateChange(napi_env env, NapiAVSessionController* napiController,
                                           napi_value param, napi_value callback);
    static napi_status OnValidCommandChange(napi_env env, NapiAVSessionController* napiController,
                                            napi_value param, napi_value callback);
    static napi_status OnOutputDeviceChange(napi_env env, NapiAVSessionController* napiController,
                                            napi_value param, napi_value callback);
    static napi_status OnSessionEventChange(napi_env env, NapiAVSessionController* napiController,
                                            napi_value param, napi_value callback);
    static napi_status OnQueueItemsChange(napi_env env, NapiAVSessionController* napiController,
        napi_value param, napi_value callback);
    static napi_status OnQueueTitleChange(napi_env env, NapiAVSessionController* napiController,
        napi_value param, napi_value callback);
    static napi_status OnExtrasChange(napi_env env, NapiAVSessionController* napiController,
        napi_value param, napi_value callback);

    static napi_status OffAVCallMetaDataChange(napi_env env, NapiAVSessionController* napiController,
        napi_value callback);
    static napi_status OffAVCallStateChange(napi_env env, NapiAVSessionController* napiController,
        napi_value callback);
    static napi_status OffSessionDestroy(napi_env env, NapiAVSessionController* napiController, napi_value callback);
    static napi_status OffPlaybackStateChange(napi_env env, NapiAVSessionController* napiController,
                                              napi_value callback);
    static napi_status OffMetaDataChange(napi_env env, NapiAVSessionController* napiController, napi_value callback);
    static napi_status OffActiveStateChange(napi_env env, NapiAVSessionController* napiController, napi_value callback);
    static napi_status OffValidCommandChange(napi_env env, NapiAVSessionController* napiController,
                                             napi_value callback);
    static napi_status OffOutputDeviceChange(napi_env env, NapiAVSessionController* napiController,
                                             napi_value callback);
    static napi_status OffSessionEventChange(napi_env env, NapiAVSessionController* napiController,
                                             napi_value callback);
    static napi_status OffQueueItemsChange(napi_env env, NapiAVSessionController* napiController,
        napi_value callback);
    static napi_status OffQueueTitleChange(napi_env env, NapiAVSessionController* napiController,
        napi_value callback);
    static napi_status OffExtrasChange(napi_env env, NapiAVSessionController* napiController,
        napi_value callback);

    static napi_status SetAVCallMetaFilter(napi_env env, NapiAVSessionController* napiController, napi_value filter);
    static napi_status SetAVCallStateFilter(napi_env env, NapiAVSessionController* napiController, napi_value filter);
    static napi_status SetPlaybackStateFilter(napi_env env, NapiAVSessionController* napiController,
                                              napi_value filter);
    static napi_status SetMetaFilter(napi_env env, NapiAVSessionController* napiController, napi_value filter);
    static napi_status RegisterCallback(napi_env env, const std::shared_ptr<ContextBase>& context,
                                        const std::string& eventName, napi_value filter, napi_value callback);
    static napi_status DoRegisterCallback(napi_env env, NapiAVSessionController* napiController);
    static void ErrCodeToMessage(int32_t errCode, std::string& message);

    napi_ref wrapperRef_ {};
    std::string sessionId_;
    std::shared_ptr<AVSessionController> controller_;
    std::shared_ptr<NapiAVControllerCallback> callback_;
    static std::mutex uvMutex_;
    static std::mutex controllerListMutex_;

    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THREE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> EventHandlers_;
    static std::map<std::string, NapiAVSessionController> ControllerList_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVSESSION_CONTROLLER_H