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

#ifndef OHOS_AVSESSION_DESCRIPTOR_H
#define OHOS_AVSESSION_DESCRIPTOR_H

#include "parcel.h"
#include "element_name.h"

namespace OHOS::AVSession {
struct OutputDeviceInfo {
    bool isRemote_ {};
    std::vector<std::string> deviceIds_;
    std::vector<std::string> deviceNames_;
};

struct AVSessionDescriptor {
    bool WriteToParcel(Parcel& out) const;
    bool ReadFromParcel(Parcel &in);

    std::string sessionId_;
    int32_t sessionType_ {};
    std::string sessionTag_;
    AppExecFwk::ElementName elementName_;
    pid_t pid_ {};
    pid_t uid_ {};
    bool isActive_ {};
    bool isTopSession_ {};
    bool thirdPartyApp {};
    OutputDeviceInfo outputDeviceInfo_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DESCRIPTOR_H