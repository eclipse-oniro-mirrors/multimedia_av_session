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

#ifndef OHOS_ANI_ASYNC_CALLBACK_H
#define OHOS_ANI_ASYNC_CALLBACK_H

#include <chrono>
#include <mutex>
#include <functional>
#include <semaphore.h>

#include "ani.h"

namespace OHOS::AVSession {
class AniAsyncCallback final {
public:
    using AniObjectGetter = std::function<void(ani_env *env, ani_object object)>;

    explicit AniAsyncCallback(ani_env *env);
    ~AniAsyncCallback();

    struct DataContextWithFunc {
        ani_env *env;
        ani_ref& method;
        std::shared_ptr<bool> isValid;
        AniObjectGetter getter;
        std::function<bool()> checkCallbackValid;
    };

    void CallWithFunc(ani_ref& method, std::shared_ptr<bool> isValid,
        const std::function<bool()>& checkCallbackValid,
        AniObjectGetter getter = AniObjectGetter());

    static void ExecuteThreadWork(ani_env *env, DataContextWithFunc *func);

private:
    ani_env *env_ = nullptr;
    static std::mutex sWorkerMutex_;
    sem_t semaphore_ = {};
};
} // namespace OHOS::AVSession
#endif // OHOS_ANI_ASYNC_CALLBACK_H
