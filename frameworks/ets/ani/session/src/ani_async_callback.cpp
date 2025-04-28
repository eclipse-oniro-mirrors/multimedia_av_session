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

#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "ani_async_callback.h"
#include "avsession_trace.h"
#include "ani_class_name.h"
#include "ani_av_session_utils.h"

using namespace std;

namespace OHOS::AVSession {
mutex AniAsyncCallback::sWorkerMutex_;
AniAsyncCallback::AniAsyncCallback(ani_env *env) : env_(env)
{
    if (env != nullptr) {
        int res = sem_init(&semaphore_, 0, 1);
        SLOGD("loop to set sem with res %{public}d", res);
    }
}

AniAsyncCallback::~AniAsyncCallback()
{
    SLOGI("no memory leak for queue-callback");
    env_ = nullptr;
    sem_destroy(&semaphore_);
}

void AniAsyncCallback::CallWithFunc(ani_ref& method, std::shared_ptr<bool> isValid,
    const std::function<bool()>& checkCallbackValid, AniObjectGetter getter)
{
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    DataContextWithFunc *func =
        new DataContextWithFunc { env_, method, isValid, std::move(getter), checkCallbackValid };
    std::thread worker(ExecuteThreadWork, env_, func);
    worker.join();
}

void AniAsyncCallback::ExecuteThreadWork(ani_env *env, DataContextWithFunc *func)
{
    CHECK_RETURN_VOID(env != nullptr, "env is null");
    lock_guard<mutex> lock(sWorkerMutex_);
    CHECK_RETURN_VOID(func != nullptr, "UvChangeMsg is null");

    ani_vm *etsVm {};
    CHECK_RETURN_VOID(env->GetVM(&etsVm) == ANI_OK, "Get etsVm fail");

    ani_env *etsEnv {};
    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    CHECK_RETURN_VOID(etsVm != nullptr, "etsVm is null");
    CHECK_RETURN_VOID(etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv) == ANI_OK,
        "AttachCurrentThread fail");

    ani_object object = nullptr;
    if (func->getter) {
        func->getter(func->env, object);
    }

    auto fnObject = reinterpret_cast<ani_fn_object>(static_cast<ani_ref>(object));

    ani_ref cbRef {};
    env->GlobalReference_Create(func->method, &cbRef);
    std::vector<ani_ref> args = {cbRef};
    ani_ref result;
    CHECK_RETURN_VOID(etsEnv != nullptr, "etsEnv is null");
    if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
        return;
    }

    CHECK_RETURN_VOID(etsVm->DetachCurrentThread() == ANI_OK, "DetachCurrentThread fail");
}
}
