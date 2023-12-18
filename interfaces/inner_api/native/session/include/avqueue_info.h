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
#ifndef OHOS_AVQUEUE_INFO_H
#define OHOS_AVQUEUE_INFO_H

#include <bitset>
#include <memory>
#include <string>
#include <map>

#include "parcel.h"
#include "avsession_pixel_map.h"

#ifndef WINDOWS_PLATFORM
#ifndef MAC_PLATFORM
#ifndef IOS_PLATFORM
#include <malloc.h>
#endif
#endif
#endif

namespace OHOS::AVSession {
class AVQueueInfo : public Parcelable {
public:

    AVQueueInfo() = default;
    ~AVQueueInfo() = default;

    bool Unmarshalling(Parcel& data);
    bool Marshalling(Parcel& parcel) const;

    void SetBundleName(const std::string& bundleName);
    std::string GetBundleName() const;

    void SetAVQueueName(const std::string& avQueueName);
    std::string GetAVQueueName() const;

    void SetAVQueueId(const std::string& avQueueId);
    std::string GetAVQueueId() const;

    void SetAVQueueImage(const std::shared_ptr<AVSessionPixelMap>& avQueueImage);
    std::shared_ptr<AVSessionPixelMap> GetAVQueueImage() const;
    
    void SetAVQueueLength(const int32_t avQueueLength);
    int32_t GetAVQueueLength() const;

    void SetAVQueueImageUri(const std::string& avQueueImageUri);
    std::string GetAVQueueImageUri() const;

private:
    std::string bundleName_ = "";
    std::string avQueueName_ = "";
    std::string avQueueId_ = "";
    std::shared_ptr<AVSessionPixelMap> avQueueImage_ = nullptr;
    int32_t avQueueLength_ = 0;
    std::string avQueueImageUri_ = "";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVQUEUE_INFO_H