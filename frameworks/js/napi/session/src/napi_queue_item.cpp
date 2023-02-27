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

#include "napi_queue_item.h"
#include "avsession_log.h"
#include "avsession_pixel_map_adapter.h"
#include "napi_utils.h"
#include "pixel_map_napi.h"

namespace OHOS::AVSession {
std::map<std::string, NapiQueueItem::GetterType> NapiQueueItem::getterMap_ = {
    { "itemId", GetItemId },
    { "description", GetDescription },
};

std::map<int32_t, NapiQueueItem::SetterType> NapiQueueItem::setterMap_ = {
    { AVQueueItem::QUEUE_ITEM_KEY_ITEM_ID, SetItemId },
    { AVQueueItem::QUEUE_ITEM_KEY_DESCRIPTION, SetDescription },
};

napi_status NapiQueueItem::GetValue(napi_env env, napi_value in, AVQueueItem& out)
{
    std::vector<std::string> propertyNames;
    auto status = NapiUtils::GetPropertyNames(env, in, propertyNames);
    CHECK_RETURN(status == napi_ok, "get property name failed", status);

    for (const auto& name : propertyNames) {
        auto it = getterMap_.find(name);
        if (it == getterMap_.end()) {
            SLOGE("property %{public}s is not of queueitem", name.c_str());
            return napi_invalid_arg;
        }
        auto getter = it->second;
        if (getter(env, in, out) != napi_ok) {
            SLOGE("get property %{public}s failed", name.c_str());
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiQueueItem::SetValue(napi_env env, const AVQueueItem& in, napi_value& out)
{
    napi_status status = napi_create_object(env, &out);
    CHECK_RETURN((status == napi_ok) && (out != nullptr), "create object failed", status);

    for (int i = 0; i < AVQueueItem::QUEUE_ITEM_KEY_MAX; ++i) {
        auto setter = setterMap_[i];
        if (setter(env, in, out) != napi_ok) {
            SLOGE("set property %{public}d failed", i);
            return napi_generic_failure;
        }
    }
    return napi_ok;
}

napi_status NapiQueueItem::GetItemId(napi_env env, napi_value in, AVQueueItem& out)
{
    int32_t property;
    auto status = NapiUtils::GetNamedProperty(env, in, "itemId", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetItemId(property);
    return status;
}

napi_status NapiQueueItem::SetItemId(napi_env env, const AVQueueItem& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, in.GetItemId(), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "itemId", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}

napi_status NapiQueueItem::GetDescription(napi_env env, napi_value in, AVQueueItem& out)
{
    AVMediaDescription property {};
    auto status = NapiUtils::GetNamedProperty(env, in, "description", property);
    CHECK_RETURN(status == napi_ok, "get property failed", status);
    out.SetDescription(std::make_shared<AVMediaDescription>(property));
    return status;
}

napi_status NapiQueueItem::SetDescription(napi_env env, const AVQueueItem& in, napi_value& out)
{
    napi_value property {};
    auto status = NapiUtils::SetValue(env, *(in.GetDescription()), property);
    CHECK_RETURN((status == napi_ok) && (property != nullptr), "create property failed", status);
    status = napi_set_named_property(env, out, "description", property);
    CHECK_RETURN(status == napi_ok, "set property failed", status);
    return status;
}
}
