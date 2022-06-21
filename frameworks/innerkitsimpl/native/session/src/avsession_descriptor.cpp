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

#include "avsession_descriptor.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVSessionDescriptor::WriteToParcel(Parcel &out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(sessionId_), false, "write sessionId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(sessionType_), false, "write sessionType failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(sessionTag_), false, "write sessionTag failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(isActive_), false, "write isActive failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(isTopSession_), false, "write isTopSession failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(outputDeviceInfo_.isRemote_), false, "write isRemote failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteStringVector(outputDeviceInfo_.deviceIds_), false, "write deviceIds failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteStringVector(outputDeviceInfo_.deviceNames_), false, "write deviceNames failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteParcelable(&elementName_), false, "write elementName failed");
    return true;
}

bool AVSessionDescriptor::ReadFromParcel(Parcel &in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(sessionId_), false, "Read sessionId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(sessionType_), false, "Read sessionType failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(sessionTag_), false, "Read sessionTag failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isActive_), false, "Read isActive failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(isTopSession_), false, "Read isTopSession failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(outputDeviceInfo_.isRemote_), false, "Read isRemote failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadStringVector(&outputDeviceInfo_.deviceIds_), false, "Read deviceIds failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadStringVector(&outputDeviceInfo_.deviceNames_), false, "Read deviceNames failed");

    sptr elementName = in.ReadParcelable<AppExecFwk::ElementName>();
    if (elementName == nullptr) {
        SLOGE("read element name failed");
        return false;
    }
    elementName_ = *elementName;
    return true;
}
}