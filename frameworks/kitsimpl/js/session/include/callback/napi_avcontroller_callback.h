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
#include "utils/avsession_napi_utils.h"
#include "utils/uv_queue.h"

namespace OHOS {
namespace AVSession {
static const std::string AVCONTROLLER_SESSIONRELEASED_CALLBACK = "sessionDestroyed";
static const std::string PLAYBACKSTATECHANGED_CALLBACK = "playbackStateChanged";
static const std::string METADATACHANGED_CALLBACK = "metadataChanged";
static const std::string ACTIVESTATECHANGED_CALLBACK = "activeStateChanged";
static const std::string VALIDCOMMANDCHANGED_CALLBACK = "validCommandChanged";
static const std::string AVCONTROLLER_OUTPUTDEVICECHANGED_CALLBACK = "outputDeviceChanged";
static const std::string FILTER_ALL = "all";

class NapiAVControllerCallback : public AVControllerCallback,
                                 public std::enable_shared_from_this<NapiAVControllerCallback> {
public:
    explicit NapiAVControllerCallback();
    virtual ~NapiAVControllerCallback();

    void OnSessionDestroy() override;
    void OnPlaybackStateChange(const AVPlaybackState& state) override;
    void OnMetaDataChange(const AVMetaData& data) override;
    void OnActiveStateChange(bool isActive) override;
    void OnValidCommandChange(const std::vector<int32_t>& cmds) override;
    void SaveCallbackReference(const std::string& callbackName, napi_value callback, napi_env env);
    void SaveFilter(std::shared_ptr<AVSessionController>& avsessionController, const std::string& callbackName,
                    napi_value filter, napi_env env);
    void ReleaseCallbackReference(const std::string& callbackName);
    bool hasCallback(const std::string& callbackName);

private:
    void SetMetaFilter(std::shared_ptr<AVSessionController>& avsessionController,
                       napi_value filter,
                       napi_env env);
    void SetPlaybackStateFilter(std::shared_ptr<AVSessionController>& avsessionController,
                                napi_value filter,
                                napi_env env);
    void GenerateAllMetaMaskType(AVMetaData::MetaMaskType & metaMaskType);
    void SetMetaMaskTypeByNapi(AVMetaData::MetaMaskType & metaMaskType, napi_value napiMetaData, napi_env env);

    napi_env env_;
    std::mutex mutex_;
    std::shared_ptr<UvQueue> uvQueue_;
    std::shared_ptr<AVMetaData> aVMetaData_ = nullptr;
    std::map<std::string, napi_ref> bindCallbackMap = {
        {AVCONTROLLER_SESSIONRELEASED_CALLBACK, nullptr},
        {PLAYBACKSTATECHANGED_CALLBACK, nullptr},
        {METADATACHANGED_CALLBACK, nullptr},
        {ACTIVESTATECHANGED_CALLBACK, nullptr},
        {VALIDCOMMANDCHANGED_CALLBACK, nullptr},
        {AVCONTROLLER_OUTPUTDEVICECHANGED_CALLBACK, nullptr},
    };
};
} // namespace AVSession
} // namespace OHOS
#endif // OHOS_NAPI_AVCONTROLLER_CALLBACK_H
