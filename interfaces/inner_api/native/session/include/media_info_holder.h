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

#ifndef OHOS_MEDIA_INFO_HOLDER_H
#define OHOS_MEDIA_INFO_HOLDER_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avqueue_item.h"

namespace OHOS::AVSession {
class MediaInfoHolder : public Parcelable {
public:
    enum {
        MEDIA_INFO_HOLDER_KEY_CURRENT_INDEX = 0,
        MEDIA_INFO_HOLDER_KEY_PLAY_INFOS = 1,
        MEDIA_INFO_HOLDER_KEY_MAX = 2,
    };

    MediaInfoHolder() = default;
    ~MediaInfoHolder() = default;

    static MediaInfoHolder* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetCurrentIndex(const int32_t& currentIndex);
    const int32_t& GetCurrentIndex() const;

    void SetPlayInfos(const std::vector<AVQueueItem>& playInfos);
    const std::vector<AVQueueItem>& GetPlayInfos() const;

    bool IsValid() const;

    void Reset();

private:
    int32_t currentIndex_ = 0;
    std::vector<AVQueueItem> playInfos_ = {};
};
} // namespace OHOS::AVSession
#endif // OHOS_MEDIA_INFO_HOLDER_H
