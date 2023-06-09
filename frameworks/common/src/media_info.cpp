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

#include "media_info.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool MediaInfo::WriteToParcel(Parcel& out) const
{
    CHECK_AND_RETURN_RET_LOG(out.WriteString(mediaId_), false, "write mediaId failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteString(mediaUrl_), false, "write mediaUrl failed");
    CHECK_AND_RETURN_RET_LOG(out.WriteInt32(startPosition_), false, "write mediaInfo failed");
    return true;
}

bool MediaInfo::ReadFromParcel(Parcel& in)
{
    CHECK_AND_RETURN_RET_LOG(in.ReadString(mediaId_), false, "Read mediaId failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadString(mediaUrl_), false, "Read mediaUrl failed");
    CHECK_AND_RETURN_RET_LOG(in.ReadInt32(startPosition_), false, "Read mediaInfo failed");
    return true;
}
} // namespace OHOS::AVSession
