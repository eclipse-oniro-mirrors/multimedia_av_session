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
#ifndef PLUGIN_LIB_H
#define PLUGIN_LIB_H

#include <string>
#include "nocopyable.h"

namespace OHOS::AVSession {

class PluginLib {
public:
    DISALLOW_COPY_AND_MOVE(PluginLib);
    explicit PluginLib(const std::string &libName);
    ~PluginLib();
    void *LoadSymbol(const std::string &symbolName);

private:
    void LogDlfcnErr(const std::string &desc);
    static std::string GetRealPath(const std::string &path);
    static bool CheckPathExist(const std::string &path);

    std::string libName_;
    void *handle_;
};
}   // namespace OHOS::AVSession
#endif // PLUGIN_LIB_H