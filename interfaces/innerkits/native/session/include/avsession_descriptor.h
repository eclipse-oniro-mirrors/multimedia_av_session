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

#ifndef OHOS_AVSESSION_DESCRIPTOR_H
#define OHOS_AVSESSION_DESCRIPTOR_H

#include "parcel.h"

namespace OHOS::AVSession {
struct AVSessionDescriptor {
    enum {
        SESSION_TYPE_AUDIO,
        SESSION_TYPE_VIDEO
    };

    bool WriteToParcel(Parcel& out) const
    {
        return out.WriteInt32(sessionId_) &&
            out.WriteInt32(sessionType_) &&
            out.WriteString(sessionTag_) &&
            out.WriteString(bundleName_) &&
            out.WriteString(abilityName_) &&
            out.WriteBool(isActive_) &&
            out.WriteBool(isTopSession_) &&
            out.WriteBool(isRemote_) &&
            out.WriteString(remoteDeviceId_);
    }

    bool ReadFromParcel(Parcel &in)
    {
        return in.ReadInt32(sessionId_) &&
            in.ReadInt32(sessionType_) &&
            in.ReadString(sessionTag_) &&
            in.ReadString(bundleName_) &&
            in.ReadString(abilityName_) &&
            in.ReadBool(isActive_) &&
            in.ReadBool(isTopSession_) &&
            in.ReadBool(isRemote_) &&
            in.ReadString(remoteDeviceId_);
    }

    int32_t sessionId_;
    int32_t sessionType_;
    std::string sessionTag_;
    std::string bundleName_;
    std::string abilityName_;
    bool isActive_;
    bool isTopSession_;
    bool isRemote_;
    std::string remoteDeviceId_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_DESCRIPTOR_H