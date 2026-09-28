/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_COMMAND_INFO_H
#define OHOS_COMMAND_INFO_H

#include <string>

#include "parcel.h"

namespace OHOS::AVSession {

class CommandInfo : public Parcelable {
public:
    CommandInfo();
    ~CommandInfo() override;

    void Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    int32_t SetCallerDeviceId(const std::string& callerDeviceId);
    int32_t GetCallerDeviceId(std::string& callerDeviceId) const;

    int32_t SetCallerBundleName(const std::string& callerBundleName);
    int32_t GetCallerBundleName(std::string& callerBundleName) const;

    int32_t SetCallerModuleName(const std::string& callerModuleName);
    int32_t GetCallerModuleName(std::string& callerModuleName) const;

    int32_t SetCallerType(const std::string& callerType);
    int32_t GetCallerType(std::string& callerType) const;

private:
    std::string callerDeviceId_;
    std::string callerBundleName_;
    std::string callerModuleName_;
    std::string callerType_;
};

class ColdStartInfo : public Parcelable {
public:
    ColdStartInfo() = default;
    ~ColdStartInfo() override = default;
 
    bool Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    int32_t SetControlCommand(int32_t controlCommand);
    int32_t GetControlCommand() const { return controlCommand_; }

    int32_t SetIsPlayList(int32_t isPlayList);
    int32_t GetIsPlayList() const { return isPlayList_; }

private:
    int32_t controlCommand_ {0};
    int32_t isPlayList_ {1};
};
}
#endif // OHOS_COMMAND_INFO_H