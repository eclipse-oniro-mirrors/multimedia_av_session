/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef LOG_TAG
#define LOG_TAG "TaiheQueueItem"
#endif

#include "taihe_queue_item.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "taihe_media_description.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::map<std::string, TaiheQueueItem::GetterType> TaiheQueueItem::getterMap_ = {
    {"itemId", GetItemId},
    {"description", GetDescription},
};

std::map<int32_t, TaiheQueueItem::SetterType> TaiheQueueItem::setterMap_ = {
    {OHOS::AVSession::AVQueueItem::QUEUE_ITEM_KEY_ITEM_ID, SetItemId},
    {OHOS::AVSession::AVQueueItem::QUEUE_ITEM_KEY_DESCRIPTION, SetDescription},
};

int32_t TaiheQueueItem::GetAVQueueItem(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out)
{
    for (const auto &[name, getter] : getterMap_) {
        SLOGD("GetAVQueueItem get property %{public}s", name.c_str());
        if (getter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("GetAVQueueItem get property %{public}s failed", name.c_str());
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheQueueItem::SetAVQueueItem(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out)
{
    for (int32_t i = 0; i < OHOS::AVSession::AVQueueItem::QUEUE_ITEM_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(in, out) != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetAVQueueItem set property %{public}d failed", i);
            return OHOS::AVSession::ERR_INVALID_PARAM;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVQueueItem TaiheQueueItem::CreateUndefinedAVQueueItem()
{
    AVQueueItem item {
        .itemId = 0,
        .description = optional<AVMediaDescription>(std::nullopt),
    };
    return item;
}

int32_t TaiheQueueItem::GetItemId(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out)
{
    out.SetItemId(in.itemId);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheQueueItem::SetItemId(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out)
{
    out.itemId = in.GetItemId();
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheQueueItem::GetDescription(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out)
{
    if (in.description.has_value()) {
        OHOS::AVSession::AVMediaDescription property {};
        int32_t status = TaiheMediaDescription::GetAVMediaDescription(in.description.value(), property);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Get description failed", status);
        out.SetDescription(std::make_shared<OHOS::AVSession::AVMediaDescription>(property));
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t TaiheQueueItem::SetDescription(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out)
{
    std::shared_ptr<OHOS::AVSession::AVMediaDescription> descriptionPtr = in.GetDescription();
    if (descriptionPtr == nullptr) {
        out.description = optional<AVMediaDescription>(std::nullopt);
    } else {
        AVMediaDescription property = TaiheMediaDescription::CreateUndefinedAVMediaDescription();
        int32_t status = TaiheMediaDescription::SetAVMediaDescription(*descriptionPtr, property);
        CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "Set description failed", status);
        out.description = optional<AVMediaDescription>(std::in_place_t {}, property);
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}
} // namespace ANI::AVSession