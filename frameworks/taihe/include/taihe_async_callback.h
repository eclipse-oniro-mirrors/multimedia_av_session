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

#ifndef TAIHE_ASYNC_CALLBACK_H
#define TAIHE_ASYNC_CALLBACK_H

#include <functional>

#include "avsession_log.h"
#include "taihe_headers.h"
#include "taihe_work.h"
#include "event_handler.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAsyncCallback final : public std::enable_shared_from_this<TaiheAsyncCallback> {
public:
    using TaiheFuncExecute = std::function<void(std::shared_ptr<uintptr_t> method)>;

    explicit TaiheAsyncCallback(ani_env *env, std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler);
    ~TaiheAsyncCallback();

    ani_env* GetEnv() const;

    void Call(std::shared_ptr<uintptr_t> method, TaiheFuncExecute execute = TaiheFuncExecute());

    void CallWithFunc(std::shared_ptr<uintptr_t> method, std::shared_ptr<bool> isValid,
        const std::function<bool()>& checkCallbackValid, TaiheFuncExecute execute = TaiheFuncExecute());

private:
    struct DataContext {
        std::shared_ptr<uintptr_t> method;
        TaiheFuncExecute execute;
    };

    struct DataContextWithFunc {
        std::shared_ptr<uintptr_t> method;
        std::shared_ptr<bool> isValid;
        TaiheFuncExecute execute;
        std::function<bool()> checkCallbackValid;
    };

    static void ThreadSafeCallbackWork(ani_env* env, DataContextWithFunc* event);
    static void ThreadCallbackWork(ani_env* env, DataContext* event);

    ani_env *env_ = nullptr;
    static std::mutex sWorkerMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
};
} // namespace ANI::AVSession
#endif // TAIHE_ASYNC_CALLBACK_H