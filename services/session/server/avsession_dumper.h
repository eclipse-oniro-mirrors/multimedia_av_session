/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_DUMP_HELPER_H
#define OHOS_AVSESSION_DUMP_HELPER_H

#include <string>
#include "avcontroller_item.h"

namespace OHOS::AVSession {
class AVSessionDumper {
public:
    AVSessionDumper()= default;
    ~AVSessionDumper() = default;
    void Dump(const std::vector<std::string>& args, std::string& result, std::map<pid_t,
              std::list<sptr<AVControllerItem>>> controllers) const;

private:
    void ShowHelp(std::string& result) const;
    void ShowMetaData(std::string &result, std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers) const;
    void ProcessParameter(const std::string& arg, std::string& result,
        std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers) const;
    void ShowIllegalInfo(std::string& result) const;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DUMP_HELPER_H