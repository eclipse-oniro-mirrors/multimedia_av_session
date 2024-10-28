/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CJ_AVSESSION_MEDIA_DESCRIPTION_H
#define OHOS_CJ_AVSESSION_MEDIA_DESCRIPTION_H

#include <map>
#include <string>

#include "singleton.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {

class FfiMediaDescriptionHelper {
    DECLARE_DELAYED_SINGLETON(FfiMediaDescriptionHelper);
public:
    DISALLOW_COPY_AND_MOVE(FfiMediaDescriptionHelper);
    int32_t GetMediaDescriptionDisplayTags(CAVMediaDescription &mediaDescription);
    int32_t SetMediaDescriptionDisplayTags(const CAVMediaDescription &mediaDescription);

    int32_t GetMediaDescriptionDataSrc(CAVMediaDescription &mediaDescription);
    int32_t SetMediaDescriptionDataSrc(const CAVMediaDescription &mediaDescription);

private:
    std::map<std::string, int32_t> displayTagsMap;
    std::map<std::string, CAVDataSrcDescriptor> dataSrcMap;
};

#define FFI_MD_HELPER OHOS::DelayedSingleton<FfiMediaDescriptionHelper>::GetInstance()

} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_MEDIA_DESCRIPTION_H