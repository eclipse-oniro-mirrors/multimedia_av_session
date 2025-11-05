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

    int32_t SetDeviceId(const std::string& deviceId);
    int32_t GetDeviceId(std::string& deviceId) const;

    int32_t SetBundleName(const std::string& bundleName);
    int32_t GetBundleName(std::string& bundleName) const;

    int32_t SetModuleName(const std::string& moduleName);
    int32_t GetModuleName(std::string& moduleName) const;

    int32_t SetPlayType(const std::string& playType);
    int32_t GetPlayType(std::string& playType) const;

private:
    std::string deviceId_;
    std::string bundleName_;
    std::string moduleName_;
    std::string playType_;
};
}
#endif // OHOS_COMMAND_INFO_H