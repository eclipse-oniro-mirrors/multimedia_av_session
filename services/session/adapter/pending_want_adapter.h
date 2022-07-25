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
#ifndef AVSESSION_PENDING_WANT_ADAPTER_H
#define AVSESSION_PENDING_WANT_ADAPTER_H

#include "iremote_object.h"
#include "parcel.h"

namespace OHOS::AVSession {
class PendingWantAdapter final : public std::enable_shared_from_this<PendingWantAdapter>, public Parcelable {
public:
    PendingWantAdapter() {};
    virtual ~PendingWantAdapter() = default;

    bool Marshalling(Parcel &parcel) const override
    {
        if (target_ == nullptr || !parcel.WriteObject<IRemoteObject>(target_)) {
            return false;
        }
        return true;
    }

    static PendingWantAdapter *Unmarshalling(Parcel &parcel)
    {
        PendingWantAdapter *pendingWant = new (std::nothrow) PendingWantAdapter();
        if (pendingWant == nullptr) {
            return nullptr;
        }
        sptr<IRemoteObject> target = parcel.ReadObject<IRemoteObject>();
        if (target == nullptr) {
            delete pendingWant;
            return nullptr;
        }
        pendingWant->SetTarget(target);
        return pendingWant;
    }

    void SetTarget(const sptr<IRemoteObject> &target)
    {
        target_ = target;
    }

private:
    sptr<IRemoteObject> target_;
};
} // namespace OHOS::AVSession
#endif // AVSESSION_PENDING_WANT_ADAPTER_H