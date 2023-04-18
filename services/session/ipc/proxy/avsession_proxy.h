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

#ifndef OHOS_AVSESSION_PROXY_H
#define OHOS_AVSESSION_PROXY_H

#include "iav_session.h"
#include "iremote_proxy.h"
#include "want_agent.h"
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

    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) override;

    int32_t Activate() override;

    int32_t Deactivate() override;

    bool IsActive() override;

    int32_t Destroy() override;

    int32_t AddSupportCommand(const int32_t cmd) override;

    int32_t DeleteSupportCommand(const int32_t cmd) override;

    int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;

protected:
    int32_t RegisterCallbackInner(const sptr<IAVSessionCallback>& callback) override;
    sptr<IRemoteObject> GetControllerInner() override;

private:
    sptr<IAVSessionCallback> callback_;
    static inline BrokerDelegator<AVSessionProxy> delegator_;
    bool isDestroyed_ = {};
    std::shared_ptr<AVSessionController> controller_;
};
}
#endif // OHOS_AVSESSION_PROXY_H