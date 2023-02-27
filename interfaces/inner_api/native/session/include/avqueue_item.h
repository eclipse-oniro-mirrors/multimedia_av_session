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

#ifndef OHOS_AVQUEUE_ITEM_H
#define OHOS_AVQUEUE_ITEM_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avmedia_description.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
class AVQueueItem : public Parcelable {
public:
    enum {
        QUEUE_ITEM_KEY_ITEM_ID = 0,
        QUEUE_ITEM_KEY_DESCRIPTION = 1,
        QUEUE_ITEM_KEY_MAX = 2
    };

    AVQueueItem() = default;
    ~AVQueueItem() = default;

    static AVQueueItem* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetItemId(int32_t itemId);
    int32_t GetItemId() const;

    void SetDescription(const std::shared_ptr<AVMediaDescription>& description);
    std::shared_ptr<AVMediaDescription> GetDescription() const;

    void Reset();

private:
    int32_t itemId_ = 0;
    std::shared_ptr<AVMediaDescription> description_ = nullptr;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVQUEUE_ITEM_H
