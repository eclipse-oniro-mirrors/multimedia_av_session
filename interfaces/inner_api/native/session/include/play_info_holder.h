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

#ifndef OHOS_PLAY_INFO_HOLDER_H
#define OHOS_PLAY_INFO_HOLDER_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "play_info.h"

namespace OHOS::AVSession {
class PlayInfoHolder : public Parcelable {
public:
    enum {
        PLAY_INFO_HOLDER_KEY_CURRENT_INDEX = 0,
        PLAY_INFO_HOLDER_KEY_PLAY_INFOS = 1,
        PLAY_INFO_HOLDER_KEY_MAX = 2
    };

    PlayInfoHolder() = default;
    ~PlayInfoHolder() = default;

    static PlayInfoHolder* Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const override;

    void SetCurrentIndex(int32_t currentIndex);
    int32_t GetCurrentTime() const;

    void SetPlayInfos(const std::vector<std::shared_ptr<PlayInfo>>& playInfos);

    const std::vector<std::shared_ptr<PlayInfo>>& GetPlayInfos() const;

    bool IsValid() const;

    void Reset();

private:
    int32_t currentIndex_ = 0;
    std::vector<std::shared_ptr<PlayInfo>> playInfos_ = {};
};
} // namespace OHOS::AVSession
#endif // OHOS_PLAY_INFO_HOLDER_H
