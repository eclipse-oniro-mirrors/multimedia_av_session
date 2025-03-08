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

#ifndef OHOS_NAPI_QUEUE_ITEM_H
#define OHOS_NAPI_QUEUE_ITEM_H

#include "avmedia_description.h"
#include "avqueue_item.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiQueueItem {
public:
    static napi_status GetValue(napi_env env, napi_value in, AVQueueItem& out);
    static napi_status SetValue(napi_env env, const AVQueueItem& in, napi_value& out);

    using GetterType = std::function<napi_status(napi_env, napi_value in, AVQueueItem& out)>;
    using SetterType = std::function<napi_status(napi_env env, const AVQueueItem& in, napi_value& out)>;

    static napi_status GetDataSrc(napi_env env, const napi_value in, napi_value* fileSize, napi_value* callback);

private:
    static napi_status GetItemId(napi_env env, napi_value in, AVQueueItem& out);
    static napi_status SetItemId(napi_env env, const AVQueueItem& in, napi_value& out);

    static napi_status GetDescription(napi_env env, napi_value in, AVQueueItem& out);
    static napi_status SetDescription(napi_env env, const AVQueueItem& in, napi_value& out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;

    static constexpr int GETTER_INDEX = 0;
    static constexpr int SETTER_INDEX = 1;
    static constexpr int ENUM_INDEX = 2;
};
}
#endif // OHOS_NAPI_QUEUE_ITEM_H
