/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "napi_async_callback.h"
#include <memory>

namespace OHOS::AVSession {
NapiAsyncCallback::NapiAsyncCallback(napi_env env) : env_(env)
{
    if (env != nullptr) {
        napi_get_uv_event_loop(env, &loop_);
    }
}

NapiAsyncCallback::~NapiAsyncCallback()
{
    SLOGE("no memory leak for queue-callback");
    env_ = nullptr;
}

napi_env NapiAsyncCallback::GetEnv() const
{
    return env_;
}

void NapiAsyncCallback::AfterWorkCallback(uv_work_t *work, int aStatus)
{
    std::shared_ptr<DataContext> context(static_cast<DataContext*>(work->data), [work](DataContext* ptr) {
        delete ptr;
        delete work;
    });

    int argc = 0;
    napi_value argv[ARGC_MAX] = { nullptr };
    if (context->getter) {
        argc = ARGC_MAX;
        context->getter(context->env, argc, argv);
    }

    SLOGI("queue uv_after_work_cb");
    napi_value global {};
    napi_get_global(context->env, &global);
    napi_value function {};
    napi_get_reference_value(context->env, context->method, &function);
    napi_value result;
    napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
}

void NapiAsyncCallback::Call(napi_ref method, NapiArgsGetter getter)
{
    if (loop_ == nullptr) {
        SLOGE("loop_ is nullptr");
        return;
    }
    if (method == nullptr) {
        SLOGE("method is nullptr");
    }

    auto* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        SLOGE("no memory for uv_work_t");
        return;
    }

    work->data = new DataContext{ env_, method, std::move(getter) };
    int res = uv_queue_work(loop_, work, [](uv_work_t* work) {}, AfterWorkCallback);
    if (res != 0) {
        SLOGE("uv queue work failed");
    }
}
}