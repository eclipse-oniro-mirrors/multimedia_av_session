/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TAIHE_QUEUE_ITEM_H
#define TAIHE_QUEUE_ITEM_H

#include "avmedia_description.h"
#include "avqueue_item.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheQueueItem {
public:
    static int32_t GetAVQueueItem(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out);
    static int32_t SetAVQueueItem(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out);
    static AVQueueItem CreateUndefinedAVQueueItem();

    using GetterType = std::function<int32_t(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out)>;

private:
    static int32_t GetItemId(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out);
    static int32_t SetItemId(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out);

    static int32_t GetDescription(AVQueueItem const &in, OHOS::AVSession::AVQueueItem &out);
    static int32_t SetDescription(const OHOS::AVSession::AVQueueItem &in, AVQueueItem &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
};
} // namespace ANI::AVSession
#endif // TAIHE_QUEUE_ITEM_H