/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_AVCAST_CONTROLLER_H
#define OHOS_NAPI_AVCAST_CONTROLLER_H

#include "avcast_controller.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_avcast_controller_callback.h"
#include "napi_async_work.h"

namespace OHOS::AVSession {
class NapiAVCastController {
public:
    NapiAVCastController();
    ~NapiAVCastController();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_status NewInstance(napi_env env, std::shared_ptr<AVCastController>& nativeController,
        napi_value& out);

    using OnEventHandlerType = std::function<napi_status(napi_env, NapiAVCastController*, napi_value, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, NapiAVCastController*, napi_value)>;

private:
    static napi_value ConstructorCallback(napi_env env, napi_callback_info info);
    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static napi_value SendControlCommand(napi_env env, napi_callback_info info);
    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Prepare(napi_env env, napi_callback_info info);
    static napi_value GetDuration(napi_env env, napi_callback_info info);
    static napi_value GetCastAVPlaybackState(napi_env env, napi_callback_info info);
    static napi_value GetCurrentItem(napi_env env, napi_callback_info info);
    static napi_value getValidCommands(napi_env env, napi_callback_info info);
    static napi_value SetDisplaySurface(napi_env env, napi_callback_info info);
    static napi_status SetCastPlaybackStateFilter(napi_env env, NapiAVCastController *napiCastController,
        napi_value filter);

    static napi_status OnPlaybackStateChange(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnMediaItemChange(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);

    static napi_status OnPlayNext(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnPlayPrevious(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnSeekDone(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnVideoSizeChange(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnPlayerError(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);
    static napi_status OnEndOfStream(napi_env env, NapiAVCastController* napiCastController,
        napi_value param, napi_value callback);

    static napi_status OffPlaybackStateChange(napi_env env, NapiAVCastController* napiCastController,
        napi_value callback);
    static napi_status OffMediaItemChange(napi_env env, NapiAVCastController* napiCastController, napi_value callback);
    static napi_status OffPlayNext(napi_env env, NapiAVCastController* napiCastController,
        napi_value callback);
    static napi_status OffPlayPrevious(napi_env env, NapiAVCastController* napiCastController, napi_value callback);
    static napi_status OffSeekDone(napi_env env, NapiAVCastController* napiCastController, napi_value callback);
    static napi_status OffVideoSizeChange(napi_env env, NapiAVCastController* napiCastController, napi_value callback);
    static napi_status OffPlayerError(napi_env env, NapiAVCastController* napiCastController, napi_value callback);
    static napi_status OffEndOfStream(napi_env env, NapiAVCastController* napiCastController, napi_value callback);

    static void ErrCodeToMessage(int32_t errCode, std::string& message);
    static napi_status RegisterCallback(napi_env env, const std::shared_ptr<ContextBase>& context,
        const std::string& event, napi_value filter, napi_value callback);

    napi_ref wrapperRef_ {};
    std::shared_ptr<AVCastController> castController_;
    std::shared_ptr<NapiAVCastControllerCallback> callback_;

    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THREE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;

    static std::map<std::string, std::pair<OnEventHandlerType, OffEventHandlerType>> EventHandlers_;
};
} // namespace OHOS::AVSession
#endif // OHOS_NAPI_AVCAST_CONTROLLER_H
