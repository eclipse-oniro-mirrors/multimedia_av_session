/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "av_data_src_descriptor.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool AVDataSrcDescriptor::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteInt64(fileSize), false, "write fileSize failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteBool(hasCallback), false, "write hasCallback failed");
    return true;
}

bool AVDataSrcDescriptor::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadInt64(fileSize), false, "Read fileSize failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadBool(hasCallback), false, "Read hasCallback failed");
    return true;
}
} // namespace OHOS::AVSession