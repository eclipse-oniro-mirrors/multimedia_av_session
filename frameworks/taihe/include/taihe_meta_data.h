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

#ifndef TAIHE_META_DATA_H
#define TAIHE_META_DATA_H

#include "avmeta_data.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheMetaData {
public:
    static int32_t ConvertFilter(string_view filter, OHOS::AVSession::AVMetaData::MetaMaskType &mask);
    static int32_t ConvertFilter(array<string> filter, OHOS::AVSession::AVMetaData::MetaMaskType &mask);

    static int32_t GetAVMetaData(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAVMetaData(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);
    static AVMetadata CreateUndefinedAVMetaData();

    using GetterType = std::function<int32_t(AVMetadata const &in, OHOS::AVSession::AVMetaData &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVMetaData &in, AVMetadata &out)>;

private:
    static int32_t GetAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetTitle(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetTitle(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetArtist(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetArtist(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetAuthor(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAuthor(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetAVQueueName(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAVQueueName(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetAVQueueId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAVQueueId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetAVQueueImage(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAVQueueImage(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);
    static int32_t SetAVQueueImageUri(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetBundleIcon(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetBundleIcon(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetAlbum(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetAlbum(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetWriter(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetWriter(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetComposer(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetComposer(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetDuration(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetDuration(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetMediaImage(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetMediaImage(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);
    static int32_t SetMediaImageUri(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetPublishDate(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetPublishDate(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetSubtitle(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetSubtitle(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetDescription(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetDescription(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetLyric(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetLyric(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetSingleLyricText(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetSingleLyricText(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetPreviousAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetPreviousAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetNextAssetId(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetNextAssetId(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetSkipIntervals(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetSkipIntervals(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetFilter(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetFilter(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetDisplayTags(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetDisplayTags(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static int32_t GetDrmSchemes(AVMetadata const &in, OHOS::AVSession::AVMetaData &out);
    static int32_t SetDrmSchemes(const OHOS::AVSession::AVMetaData &in, AVMetadata &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::pair<std::string, int32_t> filterMap_[OHOS::AVSession::AVMetaData::META_KEY_MAX];
};
} // namespace ANI::AVSession
#endif // TAIHE_META_DATA_H