/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#undef LOG_TAG
#define LOG_TAG "AVSessionDynamicLoader"

#include <dlfcn.h>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_dynamic_loader.h"
#include "directory_ex.h"
 
namespace OHOS {
namespace AVSession {
using namespace std;
 
AVSessionDynamicLoader::AVSessionDynamicLoader()
{
    SLOGI("AVSessionDynamicLoader ctor");
}
 
AVSessionDynamicLoader::~AVSessionDynamicLoader()
{
    SLOGI("AVSessionDynamicLoader dtor");
    for (auto iterator = dynamicLibHandle_.begin(); iterator != dynamicLibHandle_.end(); ++iterator) {
#ifndef TEST_COVERAGE
        dlclose(iterator->second);
#endif
        SLOGI("close library avsession_dynamic success: %{public}s", iterator->first.c_str());
    }
}

void* AVSessionDynamicLoader::OpenDynamicHandle(std::string dynamicLibrary)
{
    std::lock_guard loaderLock(libLock_);
    // if not opened, then open directly
    // do we need lock?
    // further optimization:
    // 1. split all dependencies to separate libraries
    // 2. just close each library not all
    char realCachePath[PATH_MAX] = { 0X00 };
    char *realPathRes = realpath(dynamicLibrary.c_str(), realCachePath);
    if (realPathRes == nullptr || dynamicLibrary.find(".so") == std::string::npos) {
        SLOGD("OpenDynamicHandle get dynamicLibrary %{public}s", dynamicLibrary.c_str());
    }
    if (dynamicLibHandle_[dynamicLibrary] == nullptr) {
        char sourceLibraryRealPath[PATH_MAX] = { 0x00 };
        if (realpath(dynamicLibrary.c_str(), sourceLibraryRealPath) == nullptr) {
            SLOGE("check avsession_dynamic path failed %{public}s", dynamicLibrary.c_str());
            return nullptr;
        }

#ifndef TEST_COVERAGE
        void* dynamicLibHandle = dlopen(sourceLibraryRealPath, RTLD_NOW);
        if (dynamicLibHandle == nullptr) {
            SLOGE("Failed to open library avsession_dynamic, reason: %{public}sn", dlerror());
            return nullptr;
        }
        SLOGI("open library %{public}s success", dynamicLibrary.c_str());
        dynamicLibHandle_[dynamicLibrary] = dynamicLibHandle;
#else
        SLOGI("in test coverage state, dlclose/dlopen may conflict with llvm");
#endif
    }
    return dynamicLibHandle_[dynamicLibrary];
}

void* AVSessionDynamicLoader::GetFuntion(std::string dynamicLibrary, std::string function)
{
    std::lock_guard loaderLock(libLock_);
    // if not opened, then open directly
    if (dynamicLibHandle_[dynamicLibrary] == nullptr) {
        OpenDynamicHandle(dynamicLibrary);
    }

    void* handle = nullptr;
    if (dynamicLibHandle_[dynamicLibrary] != nullptr) {
        handle = dlsym(dynamicLibHandle_[dynamicLibrary], function.c_str());
        if (handle == nullptr) {
            SLOGE("Failed to load %{public}s, reason: %{public}sn", function.c_str(), dlerror());
            return nullptr;
        }
        SLOGI("GetFuntion %{public}s success", function.c_str());
    }
    return handle;
}

void AVSessionDynamicLoader::CloseDynamicHandle(std::string dynamicLibrary)
{
    std::lock_guard loaderLock(libLock_);
    // if already opened, then close all
    if (dynamicLibHandle_[dynamicLibrary] != nullptr) {
#ifndef TEST_COVERAGE
        dlclose(dynamicLibHandle_[dynamicLibrary]);
#endif
        dynamicLibHandle_[dynamicLibrary] = nullptr;
        SLOGI("close library avsession_dynamic success: %{public}s", dynamicLibrary.c_str());
    }
}
 
}  // namespace AVSession
}  // namespace OHOS