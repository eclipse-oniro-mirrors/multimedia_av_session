/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_PROXY_H
#define OHOS_AVSESSION_PROXY_H

#include "iav_session.h"
#include "iremote_proxy.h"
#include "want_agent.h"
#include "avcall_meta_data.h"
#include "avcall_state.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"

namespace OHOS::AVSession {
class AVSessionProxy : public IRemoteProxy<IAVSession> {
public:
    explicit AVSessionProxy(const sptr<IRemoteObject>& impl);

    ~AVSessionProxy() override;

    std::string GetSessionId() override;

    std::string GetSessionType() override;

    int32_t SetAVCallMetaData(const AVCallMetaData& avCallMetaData) override;

    int32_t SetAVCallState(const AVCallState& avCallState) override;

    int32_t GetAVMetaData(AVMetaData& meta) override;

    int32_t SetAVMetaData(const AVMetaData& meta) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;

    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueTitle(std::string& title) override;

    int32_t SetAVQueueTitle(const std::string& title) override;

    int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) override;

    int32_t GetExtras(AAFwk::WantParams& extras) override;

    int32_t SetExtras(const AAFwk::WantParams& extras) override;

    std::shared_ptr<AVSessionController> GetController() override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override;

    int32_t StartCastDisplayListener() override;

    int32_t StopCastDisplayListener() override;

    int32_t GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays) override;
#endif

    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) override;

    int32_t Activate() override;

    int32_t Deactivate() override;

    bool IsActive() override;

    int32_t Destroy() override;

    int32_t AddSupportCommand(const int32_t cmd) override;

    int32_t DeleteSupportCommand(const int32_t cmd) override;

    int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t ReleaseCast() override;
#endif

protected:
    int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) override;
    sptr<IRemoteObject> GetControllerInner() override;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    sptr<IRemoteObject> GetAVCastControllerInner() override;
#endif

private:
    int32_t GetPixelMapBuffer(AVMetaData& metaData, MessageParcel& data);
    sptr<IAVSessionCallback> callback_;
    static inline BrokerDelegator<AVSessionProxy> delegator_;
    bool isDestroyed_ = {};
    std::shared_ptr<AVSessionController> controller_;
    const size_t DEFAULT_IPC_CAPACITY = 1048576; // Increase the IPC default capacity(200K) to 1M

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> castController_;
#endif
};
}
#endif // OHOS_AVSESSION_PROXY_H