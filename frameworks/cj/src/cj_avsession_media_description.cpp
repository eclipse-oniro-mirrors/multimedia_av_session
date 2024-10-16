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

#include "cj_avsession_media_description.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "cj_avsession_utils.h"

namespace OHOS::AVSession {

FfiMediaDescriptionHelper::FfiMediaDescriptionHelper() {}

FfiMediaDescriptionHelper::~FfiMediaDescriptionHelper() {}

int32_t FfiMediaDescriptionHelper::GetMediaDescriptionDisplayTags(CAVMediaDescription &mediaDescription)
{
    std::string str(mediaDescription.mediaId);
    if (displayTagsMap.count(str) <= 0) {
        mediaDescription.displayTags = displayTagsMap[str];
        return CJNO_ERROR;
    }
    SLOGE("GetMediaDescriptionDisplayTags failed");
    return AVSESSION_ERROR;
}

int32_t FfiMediaDescriptionHelper::SetMediaDescriptionDisplayTags(const CAVMediaDescription &mediaDescription)
{
    std::string str(mediaDescription.mediaId);
    displayTagsMap[str] = mediaDescription.displayTags;
    return CJNO_ERROR;
}

int32_t FfiMediaDescriptionHelper::GetMediaDescriptionDataSrc(CAVMediaDescription &mediaDescription)
{
    std::string str(mediaDescription.mediaId);
    if (dataSrcMap.count(str) <= 0) {
        mediaDescription.dataSrc = dataSrcMap[str];
        return CJNO_ERROR;
    }
    SLOGE("GetMediaDescriptionDataSrc failed");
    return AVSESSION_ERROR;
}

int32_t FfiMediaDescriptionHelper::SetMediaDescriptionDataSrc(const CAVMediaDescription &mediaDescription)
{
    std::string str(mediaDescription.mediaId);
    dataSrcMap[str] = mediaDescription.dataSrc;
    return CJNO_ERROR;
}

} // namespace AVSession::OHOS