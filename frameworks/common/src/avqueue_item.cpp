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

#include "avqueue_item.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVQueueItem::Marshalling(Parcel& parcel) const
{
    return parcel.WriteInt32(itemId_) &&
        parcel.WriteParcelable(description_.get());
}

AVQueueItem *AVQueueItem::Unmarshalling(Parcel& data)
{
    auto *result = new (std::nothrow) AVQueueItem();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new AVMetaData failed");
    if (!data.ReadInt32(result->itemId_)) {
        SLOGE("read AVQueueItem failed");
        delete result;
        return nullptr;
    }
    result->description_ = std::shared_ptr<AVMediaDescription>(data.ReadParcelable<AVMediaDescription>());
    if (result->description_ == nullptr) {
        SLOGE("read AVQueueItem - description failed");
        delete result;
        return nullptr;
    }
    return result;
}

void AVQueueItem::SetItemId(int32_t itemId)
{
    itemId_ = itemId;
}

int32_t AVQueueItem::GetItemId() const
{
    return itemId_;
}

void AVQueueItem::SetDescription(const std::shared_ptr<AVMediaDescription>& description)
{
    description_ = description;
}

std::shared_ptr<AVMediaDescription> AVQueueItem::GetDescription() const
{
    return description_;
}

void AVQueueItem::Reset()
{
    itemId_ = 0;
    description_ = nullptr;
}
} // namespace OHOS::AVSession
