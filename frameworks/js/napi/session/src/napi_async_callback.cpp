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
        SLOGI("loop to set sem with res %{public}d", res);
    }
}

NapiAsyncCallback::~NapiAsyncCallback()
{
    SLOGD("no memory leak for queue-callback");
    env_ = nullptr;
    sem_destroy(&semaphore_);
}

napi_env NapiAsyncCallback::GetEnv() const
{
    return env_;
}

void NapiAsyncCallback::AfterWorkCallback(uv_work_t* work, int aStatus)
{
    AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::AfterWorkCallback");
    std::shared_ptr<DataContext> context(static_cast<DataContext*>(work->data), [work](DataContext* ptr) {
        delete ptr;
        delete work;
    });

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);

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
    napi_close_handle_scope(context->env, scope);
}

void NapiAsyncCallback::AfterWorkCallbackWithFlag(uv_work_t* work, int aStatus)
{
    AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::AfterWorkCallbackWithFlag");
    std::shared_ptr<DataContextWithFlag> context(static_cast<DataContextWithFlag*>(work->data),
        [work](DataContextWithFlag* ptr) {
        delete ptr;
        delete work;
    });

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);

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
    SLOGI("callback with flag");
    if (!*context->isValid) {
        SLOGE("AfterWorkCallbackWithFlag callback when callback is invalid");
        napi_close_handle_scope(context->env, scope);
        return;
    }
    SLOGI("callback with ref %{public}p, %{public}p", &(context->method), *(&(context->method)));
    napi_get_reference_value(context->env, context->method, &function);
    napi_value result;
    napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
    napi_close_handle_scope(context->env, scope);
}

void NapiAsyncCallback::AfterWorkCallbackWithFunc(uv_work_t* work, int aStatus)
{
    AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::AfterWorkCallbackWithFunc");
    std::shared_ptr<DataContextWithFunc> context(static_cast<DataContextWithFunc*>(work->data),
        [work](DataContextWithFunc* ptr) {
        delete ptr;
        delete work;
    });

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);

    int argc = 0;
    napi_value argv[ARGC_MAX] = { nullptr };
    if (context->getter) {
        argc = ARGC_MAX;
        context->getter(context->env, argc, argv);
    }

    SLOGI("queue uv_after_work_cb");
    if (!*context->isValid) {
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
    napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
    napi_close_handle_scope(context->env, scope);
}

void NapiAsyncCallback::AfterWorkCallbackWithOrder(uv_work_t* work, int aStatus)
{
    AVSESSION_TRACE_SYNC_START("NapiAsyncCallback::AfterWorkCallbackWithOrder");
    std::shared_ptr<DataContextWithOrder> context(static_cast<DataContextWithOrder*>(work->data),
        [work](DataContextWithOrder* ptr) {
        delete ptr;
        delete work;
    });

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);

    int argc = 0;
    napi_value argv[ARGC_MAX] = { nullptr };
    if (context->getter) {
        argc = ARGC_MAX;
        context->getter(context->env, argc, argv);
    }

    SLOGI("queue uv_after_work_cb with state %{public}d", static_cast<int>(context->state));
    if (!*context->isValid) {
        SLOGE("AfterWorkCallbackWithOrder failed for context is invalid.");
        napi_close_handle_scope(context->env, scope);
        sem_post(context->semaphore);
        return;
    }
    napi_value global {};
    napi_get_global(context->env, &global);
    napi_value function {};
    if (!context->checkCallbackValid()) {
        SLOGE("Get func reference failed for func has been deleted.");
        napi_close_handle_scope(context->env, scope);
        sem_post(context->semaphore);
        return;
    }
    napi_get_reference_value(context->env, context->method, &function);
    napi_value result;
    if (!context->checkCallbackValid()) {
        SLOGE("Call func failed for func has been deleted.");
        napi_close_handle_scope(context->env, scope);
        sem_post(context->semaphore);
        return;
    }
    napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        SLOGE("call function failed status=%{public}d.", status);
    }
    napi_close_handle_scope(context->env, scope);
    sem_post(context->semaphore);
    SLOGI("queue uv_after_work_cb done with state %{public}d", static_cast<int>(context->state));
}

void NapiAsyncCallback::Call(napi_ref& method, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    auto* work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContext{env_, method, std::move(getter)};
    int res = uv_queue_work_with_qos(loop_, work, [](uv_work_t* work) {}, AfterWorkCallback, uv_qos_user_initiated);
    CHECK_RETURN_VOID(res == 0, "uv queue work failed");
}

void NapiAsyncCallback::CallWithFlag(napi_ref& method, std::shared_ptr<bool> isValid, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    auto* work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContextWithFlag { env_, method, isValid, std::move(getter) };
    int res = uv_queue_work_with_qos(loop_, work, [](uv_work_t* work) {}, AfterWorkCallbackWithFlag,
        uv_qos_user_initiated);
    CHECK_RETURN_VOID(res == 0, "uv queue work failed");
}

void NapiAsyncCallback::CallWithFunc(napi_ref& method, std::shared_ptr<bool> isValid,
    const std::function<bool()>& checkCallbackValid, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    auto* work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data = new DataContextWithFunc { env_, method, isValid, std::move(getter), checkCallbackValid };
    int res = uv_queue_work_with_qos(loop_, work, [](uv_work_t* work) {}, AfterWorkCallbackWithFunc,
        uv_qos_user_initiated);
    CHECK_RETURN_VOID(res == 0, "uv queue work failed");
}

void NapiAsyncCallback::CallWithOrder(napi_ref& method, std::shared_ptr<bool> isValid, int state,
    const std::function<bool()>& checkCallbackValid, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(loopOrder_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");

    struct timespec ts;
    int retForTime = clock_gettime(CLOCK_REALTIME, &ts);
    int retForSem = 0;
    if (retForTime < 0) {
        SLOGE("sem wait time get err");
    } else {
        ts.tv_sec += 1;
        retForSem = sem_timedwait(&semaphore_, &ts);
    }
    if (retForSem < 0) {
        SLOGE("sem wait fail with res:%{public}d, err:%{public}s", static_cast<int>(retForSem), strerror(errno));
        if (errno == ETIMEDOUT) {
            sem_post(&semaphore_);
            SLOGE("sem wait out of time, try release hold with sem post");
        }
    }
    SLOGI("do CallWithOrder pass sem with state %{public}d", state);

    auto* work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_VOID(work != nullptr, "no memory for uv_work_t");

    work->data =
        new DataContextWithOrder { env_, method, &semaphore_, state, isValid, std::move(getter), checkCallbackValid };
    int res = uv_queue_work_with_qos(loopOrder_, work, [](uv_work_t* work) {}, AfterWorkCallbackWithOrder,
        uv_qos_user_initiated);
    CHECK_RETURN_VOID(res == 0, "uv queue work failed");
}
}