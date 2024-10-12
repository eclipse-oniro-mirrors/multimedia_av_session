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

#include "plugin_lib.h"

#include <dlfcn.h>
#include <filesystem>
#include <string>

#include "avsession_log.h"

namespace OHOS::AVSession {

PluginLib::PluginLib(const std::string &libName)
    : libName_(GetRealPath(libName)), handle_(nullptr)
{
    if (!CheckPathExist(libName_)) {
        SLOGE("%{public}s path invalid", libName_.c_str());
        return;
    }
    handle_ = dlopen(libName_.c_str(), RTLD_NOW);
    if (handle_ == nullptr) {
        LogDlfcnErr("open lib failed");
    return;
}
SLOGI("%{public}s open succ", libName_.c_str());
}

PluginLib::~PluginLib()
{
    if (handle_ == nullptr || dlclose(handle_) != 0) {
        LogDlfcnErr("close lib failed");
    }
    SLOGI("%{public}s close succ", libName_.c_str());
}

void *PluginLib::LoadSymbol(const std::string &symbolName)
{
    if (handle_ == nullptr) {
        SLOGE("%{public}s lib is null", libName_.c_str());
    return nullptr;
    }
    void *sym = dlsym(handle_, symbolName.c_str());
    if (sym == nullptr) {
        LogDlfcnErr("load symbol [" + symbolName + "] failed");
        return nullptr;
    }
    SLOGI("%{public}s load symbol succ", symbolName.c_str());
    return sym;
}

void PluginLib::LogDlfcnErr(const std::string &desc)
{
    SLOGE("[%{public}s] %{public}s, reason = %{public}s",
        libName_.c_str(), desc.c_str(), dlerror());
    // reset errors
    dlerror();
}

std::string PluginLib::GetRealPath(const std::string &path)
{
    auto realPath = std::filesystem::weakly_canonical(path);
    return realPath.string();
}

bool PluginLib::CheckPathExist(const std::string &path)
{
    return std::filesystem::exists(path);
}

}   // namespace OHOS::AVSession