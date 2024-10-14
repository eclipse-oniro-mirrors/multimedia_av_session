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
 
#ifndef OHOS_AVSESSION_DYNAMIC_LOADER_H
#define OHOS_AVSESSION_DYNAMIC_LOADER_H
 
#include <map>
#include <memory>
#include <mutex>
#include <string>
 
namespace OHOS {
namespace AVSession {
using namespace std;
 
class AVSessionDynamicLoader {
public:
    AVSessionDynamicLoader();
    ~AVSessionDynamicLoader();
 
    void* OpenDynamicHandle(std::string dynamicLibrary);
    void CloseDynamicHandle(std::string dynamicLibrary);
    void* GetFuntion(std::string dynamicLibrary, std::string function);

private:
    std::map<std::string, void *> dynamicLibHandle_;
    std::recursive_mutex libLock_;
};
 
}  // namespace AVSession
}  // namespace OHOS
#endif // OHOS_AVSESSION_DYNAMIC_LOADER_H