/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "av_file_descriptor.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVFileDescriptor::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(fd_), false, "write fd_ failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt64(offset_), false, "write offset_ failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt64(length_), false, "write length_ failed");
    return true;
}

bool AVFileDescriptor::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(fd_), false, "Read fd_ failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt64(offset_), false, "Read offset_ failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt64(length_), false, "Read length_ failed");
    return true;
}
} // namespace OHOS::AVSession
