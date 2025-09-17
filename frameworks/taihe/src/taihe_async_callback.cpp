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
#ifndef LOG_TAG
#define LOG_TAG "TaiheAsyncCallback"
#endif

#include <thread>

#include "taihe_utils.h"
#include "taihe_async_callback.h"

namespace ANI::AVSession {
std::mutex TaiheAsyncCallback::sWorkerMutex_;
TaiheAsyncCallback::TaiheAsyncCallback(ani_env *env, std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler)
{
    if (env != nullptr) {
        env_ = env;
    }
    if (mainHandler != nullptr) {
        mainHandler_ = mainHandler;
    }
}

TaiheAsyncCallback::~TaiheAsyncCallback()
{
    SLOGI("no memory leak for queue-callback");
    env_ = nullptr;
}

ani_env* TaiheAsyncCallback::GetEnv() const
{
    return env_;
}

void TaiheAsyncCallback::Call(std::shared_ptr<uintptr_t> method, TaiheFuncExecute execute)
{
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");
    CHECK_RETURN_VOID(mainHandler_ != nullptr, "mainHandler_ is nullptr");
    DataContext *data =
        new DataContext { method, std::move(execute) };
    auto sharePtr = shared_from_this();
    auto taskCall = [data, sharePtr, this]() {
        if (sharePtr != nullptr) {
            sharePtr->ThreadCallbackWork(this->env_, data);
        }
    };
    mainHandler_->PostTask(taskCall, "Call", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TaiheAsyncCallback::CallWithFunc(std::shared_ptr<uintptr_t> method, std::shared_ptr<bool> isValid,
    const std::function<bool()>& checkCallbackValid, TaiheFuncExecute execute)
{
    CHECK_RETURN_VOID(method != nullptr, "method is nullptr");
    CHECK_RETURN_VOID(mainHandler_ != nullptr, "mainHandler_ is nullptr");
    DataContextWithFunc *data =
        new DataContextWithFunc { method, isValid, std::move(execute), checkCallbackValid };
    auto sharePtr = shared_from_this();
    auto taskCallWithFunc = [data, sharePtr, this]() {
        if (sharePtr != nullptr) {
            sharePtr->ThreadSafeCallbackWork(this->env_, data);
        }
    };
    mainHandler_->PostTask(taskCallWithFunc, "CallWithFunc", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void TaiheAsyncCallback::ThreadSafeCallbackWork(ani_env* env, DataContextWithFunc* data)
{
    std::lock_guard<std::mutex> lock(sWorkerMutex_);
    CHECK_AND_RETURN_LOG((data != nullptr) && (data->method != nullptr),
        "ThreadSafeCallbackWork: no memory");
    std::shared_ptr<DataContextWithFunc> safeContext(static_cast<DataContextWithFunc*>(data),
        [](DataContextWithFunc* ptr) {
        delete ptr;
        ptr = nullptr;
    });
    CHECK_RETURN_VOID(safeContext != nullptr, "ThreadCallbackWork: safeContext is nullptr");
    CHECK_RETURN_VOID(safeContext->isValid != nullptr, "ThreadCallbackWork: isValid is nullptr");
    if (!(*safeContext->isValid)) {
        SLOGE("ThreadSafeCallbackWork: callback is invalid");
        return;
    }
    if (!safeContext->checkCallbackValid()) {
        SLOGE("Call func failed for func has been deleted.");
        return;
    }
    do {
        SLOGI("Call func execute");
        if (safeContext->execute) {
            safeContext->execute(safeContext->method);
        }
    } while (0);
}

void TaiheAsyncCallback::ThreadCallbackWork(ani_env* env, DataContext* data)
{
    std::lock_guard<std::mutex> lock(sWorkerMutex_);
    CHECK_AND_RETURN_LOG((data != nullptr) && (data->method != nullptr),
        "ThreadSafeCallbackWork: no memory");
    std::shared_ptr<DataContext> safeContext(static_cast<DataContext*>(data),
        [](DataContext* ptr) {
        delete ptr;
        ptr = nullptr;
    });
    CHECK_RETURN_VOID(safeContext != nullptr, "ThreadCallbackWork: safeContext is nullptr");
    do {
        SLOGI("Call func execute");
        if (safeContext->execute) {
            safeContext->execute(safeContext->method);
        }
    } while (0);
}
} // namespace ANI::AVSession