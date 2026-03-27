/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COLLABORATION_MANAGER_URLCASTING_H
#define COLLABORATION_MANAGER_URLCASTING_H

#include <mutex>
#include "collaboration_manager.h"

namespace OHOS::AVSession {
class CollaborationManagerURLCasting : public CollaborationManager {
public:
    CollaborationManagerURLCasting();
    static CollaborationManagerURLCasting& GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<CollaborationManagerURLCasting> instance_;
    static std::recursive_mutex instanceLock_;
};
}   // namespace OHOS::AVSession
#endif //COLLABORATION_MANAGER_URLCASTING_H