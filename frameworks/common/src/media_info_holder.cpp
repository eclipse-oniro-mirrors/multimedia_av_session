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

#include "media_info_holder.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
bool MediaInfoHolder::Marshalling(Parcel& parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(currentIndex_), false, "write currentIndex failed");
    int32_t playInfosSize = static_cast<int32_t>(playInfos_.size());
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(playInfosSize), false, "write playInfoSize failed");
    for (auto playInfo : playInfos_) {
        CHECK_AND_RETURN_RET_LOG(playInfo.Marshalling(parcel), false, "write playInfoSize failed");
    }
    return true;
}

MediaInfoHolder *MediaInfoHolder::Unmarshalling(Parcel& data)
{
    auto *result = new (std::nothrow) MediaInfoHolder();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "result new fail");

    int32_t currentIndex;
    if (!data.ReadInt32(currentIndex))
    {
        SLOGE("write currentIndex failed");
        delete result;
        return nullptr;
    }
    
    result->currentIndex_ = currentIndex;
    int32_t playInfosSize;
    if (!data.ReadInt32(playInfosSize))
    {
        SLOGE("write playInfosSize failed");
        delete result;
        return nullptr;
    }
    int32_t maxPlayInfosSize = 1000;
    CHECK_AND_RETURN_RET_LOG((playInfosSize >= 0) && (playInfosSize < maxPlayInfosSize),
        nullptr, "playInfosSize is illegal");
    for (int i = 0; i < playInfosSize; i++) {
        AVQueueItem* queueItem = AVQueueItem::Unmarshalling(data);
        result->playInfos_.emplace_back(*queueItem);
    }
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "new MediaInfoHolder failed");
    return result;
}

void MediaInfoHolder::SetCurrentIndex(const int32_t& currentIndex)
{
    currentIndex_ = currentIndex;
}

int32_t MediaInfoHolder::GetCurrentIndex() const
{
    return currentIndex_;
}

void MediaInfoHolder::SetPlayInfos(const std::vector<AVQueueItem>& playInfos)
{
    playInfos_ = playInfos;
}

const std::vector<AVQueueItem>& MediaInfoHolder::GetPlayInfos() const
{
    return playInfos_;
}

bool MediaInfoHolder::IsValid() const
{
    return playInfos_.size() > 0;
}

void MediaInfoHolder::Reset()
{
    currentIndex_ = 0;
    playInfos_.clear();
}
} // namespace OHOS::AVSession
