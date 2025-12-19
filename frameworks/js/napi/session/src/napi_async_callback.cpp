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

#include <memory>

#include "avsession_trace.h"
#include "napi_utils.h"
#include "napi_async_callback.h"

namespace OHOS::AVSession {
NapiAsyncCallback::NapiAsyncCallback(napi_env env) : env_(env)
{
    if (env != nullptr) {
        napi_get_uv_event_loop(env, &loop_);
        napi_get_uv_event_loop(env, &loopOrder_);
        int res = sem_init(&semaphore_, 0, 1);
        SLOGD("loop to set sem with res %{public}d", res);
    }
}

NapiAsyncCallback::~NapiAsyncCallback()
{
    SLOGI("no memory leak for queue-callback");
    env_ = nullptr;
    sem_destroy(&semaphore_);
}

napi_env NapiAsyncCallback::GetEnv() const
{
    return env_;
}

void NapiAsyncCallback::Call(napi_ref& method, std::string callbackName, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    std::shared_ptr<uv_work_t> work = std::make_shared<uv_work_t>();
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContext{env_, method, std::move(getter)};
    auto task = [work] {
        AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::Call");
        std::shared_ptr<DataContext> context(static_cast<DataContext*>(work->data), [](DataContext* ptr) {
            delete ptr;
            ptr = nullptr;
        });

        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(context->env, &scope);

        int argc = 0;
        napi_value argv[ARGC_MAX] = { nullptr };
        if (context == nullptr) {
            SLOGE("context is nullptr");
            return;
        }
        if (context->getter) {
            argc = ARGC_MAX;
            context->getter(context->env, argc, argv);
        }

        napi_value global {};
        napi_get_global(context->env, &global);
        napi_value function {};
        napi_get_reference_value(context->env, context->method, &function);
        napi_value result;
        napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
        if (status != napi_ok) {
            SLOGE("call function failed status=%{public}d.", status);
        }
        napi_close_handle_scope(context->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate, callbackName.c_str())) {
        SLOGE("Call: napi_send_event fail");
    }
}

void NapiAsyncCallback::CallWithFlag(napi_ref& method, std::shared_ptr<bool> isValid, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    std::shared_ptr<uv_work_t> work = std::make_shared<uv_work_t>();
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContextWithFlag { env_, method, isValid, std::move(getter) };
    auto task = [work] {
        AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::CallWithFlag");
        std::shared_ptr<DataContextWithFlag> context(static_cast<DataContextWithFlag*>(work->data),
            [](DataContextWithFlag* ptr) {
            delete ptr;
            ptr = nullptr;
        });

        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(context->env, &scope);

        int argc = 0;
        napi_value argv[ARGC_MAX] = { nullptr };
        if (context == nullptr) {
            SLOGE("context is nullptr");
            return;
        }
        if (context->getter) {
            argc = ARGC_MAX;
            context->getter(context->env, argc, argv);
        }

        napi_value global {};
        napi_get_global(context->env, &global);
        napi_value function {};
        SLOGD("callback with flag");
        if (!*context->isValid) {
            SLOGE("AfterWorkCallbackWithFlag callback when callback is invalid");
            napi_close_handle_scope(context->env, scope);
            return;
        }
        napi_get_reference_value(context->env, context->method, &function);
        napi_value result;
        napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
        if (status != napi_ok) {
            SLOGE("call function failed status=%{public}d.", status);
        }
        napi_close_handle_scope(context->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate, "NapiAsyncCallback::CallWithFlag")) {
        SLOGE("CallWithFlag: napi_send_event fail");
    }
}

void NapiAsyncCallback::CallWithFunc(napi_ref& method, std::shared_ptr<bool> isValid,
    const std::function<bool()>& checkCallbackValid, std::string callbackName, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr && method != nullptr, "loop_ or method is nullptr");

    std::shared_ptr<uv_work_t> work = std::make_shared<uv_work_t>();
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContextWithFunc { env_, method, isValid, std::move(getter), checkCallbackValid };
    auto task = [work] {
        AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::AfterWorkCallbackWithFunc");
        std::shared_ptr<DataContextWithFunc> context(static_cast<DataContextWithFunc*>(work->data),
            [](DataContextWithFunc* ptr) {
            delete ptr;
            ptr = nullptr;
        });

        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(context->env, &scope);

        int argc = 0;
        napi_value argv[ARGC_MAX] = { nullptr };
        CHECK_RETURN_VOID(context != nullptr, "context is nullptr");
        if (context->getter) {
            argc = ARGC_MAX;
            context->getter(context->env, argc, argv);
        }

        if (!(*context->isValid)) {
            SLOGE("AfterWorkCallbackWithFunc failed for context is invalid.");
            napi_close_handle_scope(context->env, scope);
            return;
        }
        napi_value global {};
        napi_get_global(context->env, &global);
        napi_value function {};
        if (!context->checkCallbackValid()) {
            SLOGE("Get func reference failed for func has been deleted.");
            napi_close_handle_scope(context->env, scope);
            return;
        }
        napi_get_reference_value(context->env, context->method, &function);
        napi_value result;
        if (!context->checkCallbackValid()) {
            SLOGE("Call func failed for func has been deleted.");
            napi_close_handle_scope(context->env, scope);
            return;
        }
        if (napi_status::napi_ok != napi_call_function(context->env, global, function, argc, argv, &result)) {
            SLOGE("call function failed");
        }
        napi_close_handle_scope(context->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate, callbackName.c_str())) {
        SLOGE("CallWithFlag: napi_send_event fail");
    }
}
}