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
#ifndef AVSESSION_WANT_AGENT_ADAPTER_H
#define AVSESSION_WANT_AGENT_ADAPTER_H

#include "parcel.h"
#include "pending_want_adapter.h"

namespace OHOS::AVSession {
class WantAgentAdapter final : public std::enable_shared_from_this<WantAgentAdapter>, public Parcelable {
public:
    WantAgentAdapter() {};
    virtual ~WantAgentAdapter() = default;

    /**
     * @description: Marshals a Want into a Parcel.
     * Fields in the Want are marshalled separately. If any field fails to be marshalled, false is returned.
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override
    {
        if (pendingWant_ == nullptr || !parcel.WriteParcelable(pendingWant_.get())) {
            return false;
        }
        return true;
    }

    /**
     * @description: Unmarshals a Want from a Parcel.
     * Fields in the Want are unmarshalled separately. If any field fails to be unmarshalled, false is returned.
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns a Want if the unmarshalling is successful; returns nullptr otherwise.
     */
    static WantAgentAdapter *Unmarshalling(Parcel &parcel)
    {
        WantAgentAdapter *agent = new (std::nothrow) WantAgentAdapter();
        if (agent == nullptr) {
            return nullptr;
        }
        std::shared_ptr<PendingWantAdapter> pendingWant(parcel.ReadParcelable<PendingWantAdapter>());
        agent->SetPendingWant(pendingWant);
        return agent;
    }

    void SetPendingWant(const std::shared_ptr<PendingWantAdapter> &pendingWant)
    {
        pendingWant_ = pendingWant;
    }

private:
    std::shared_ptr<PendingWantAdapter> pendingWant_ = nullptr;
};
} // namespace OHOS::AVSession
#endif // AVSESSION_WANT_AGENT_ADAPTER_H