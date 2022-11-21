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

#ifndef OHOS_AVSESSION_DUMP_HELPER_H
#define OHOS_AVSESSION_DUMP_HELPER_H

#include <string>

#include "avsession_service.h"

namespace OHOS::AVSession {
class AVSessionDumper {
    using DumpActionType = void(*)(std::string& result, const AVSessionService& sessionService);
public:
    AVSessionDumper() = default;
    ~AVSessionDumper() = default;
    void Dump(const std::vector<std::string>& args, std::string& result, const AVSessionService& sessionService) const;
    void SetErrorInfo(const std::string& inErrMsg);

private:
    void ShowHelp(std::string& result) const;
    void ShowIllegalInfo(std::string& result) const;
    void ProcessParameter(const std::string& arg, std::string& result, const AVSessionService& sessionService) const;
    static void ShowMetaData(std::string& result, const AVSessionService& sessionService);
    static void ShowSessionInfo(std::string& result, const AVSessionService& sessionService);
    static void ShowControllerInfo(std::string& result, const AVSessionService& sessionService);
    static void ShowErrorInfo(std::string& result, const AVSessionService& sessionService);
    static void ShowTrustedDevicesInfo(std::string& result, const AVSessionService& sessionService);

    static std::map<std::string, AVSessionDumper::DumpActionType> funcMap_;
    static std::map<int32_t, std::string> playBackStates_;
    static std::map<int32_t, std::string> loopMode_;
    static std::vector<std::string> errMessage_;
    static std::map<int32_t, std::string> deviceTypeId_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DUMP_HELPER_H