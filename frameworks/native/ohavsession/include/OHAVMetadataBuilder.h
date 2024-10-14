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
#ifndef OHOS_OHAVSESSION_METADATA_H
#define OHOS_OHAVSESSION_METADATA_H

#include <string>
#include "native_avmetadata.h"
#include "native_avsession_errors.h"
#include "avsession_pixel_map_adapter.h"
#include "avmeta_data.h"
#include "curl/curl.h"
#include "image_source.h"
#include "pixel_map.h"

namespace OHOS::AVSession {
class OHAVMetadataBuilder {
public:
    AVMetadata_Result SetTitle(const std::string &title);
    AVMetadata_Result SetArtist(const std::string &artist);
    AVMetadata_Result SetAuthor(const std::string &author);
    AVMetadata_Result SetAlbum(const std::string &album);
    AVMetadata_Result SetWriter(const std::string &writer);
    AVMetadata_Result SetComposer(const std::string &composer);
    AVMetadata_Result SetDuration(int64_t duration);
    AVMetadata_Result SetMediaImageUri(const std::string &mediaImageUri);
    AVMetadata_Result SetSubtitle(const std::string &subtitle);
    AVMetadata_Result SetDescription(const std::string &description);
    AVMetadata_Result SetLyric(const std::string &lyric);
    AVMetadata_Result SetAssetId(const std::string &assetId);
    AVMetadata_Result SetSkipIntervals(AVMetadata_SkipIntervals intervals);
    AVMetadata_Result SetDisplayTags(int32_t tags);
    AVMetadata_Result GenerateAVMetadata(OH_AVMetadata** avMetadata);

private:
    static bool CurlSetRequestOptions(std::vector<std::uint8_t>& imgBuffer, const std::string uri);
    static bool DoDownloadInCommon(std::shared_ptr<Media::PixelMap>& pixelMap, const std::string uri);
    static int32_t DoDownload(AVMetaData& meta, const std::string uri);
    static size_t WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb, std::vector<std::uint8_t> *imgBuffer);
    std::string title_ = "";
    std::string artist_ = "";
    std::string author_ = "";
    std::string album_ = "";
    std::string writer_ = "";
    std::string composer_ = "";
    int64_t duration_ = 0;
    std::string mediaImageUri_ = "";
    std::string subtitle_ = "";
    std::string description_ = "";
    std::string lyric_ = "";
    std::string assetId_ = "";
    AVMetadata_SkipIntervals intervals_ = SECONDS_15;
    int32_t tags_ = 0;
    static constexpr size_t TIME_OUT_SECOND = 5;
    static constexpr int HTTP_ERROR_CODE = 400;
};
}

#endif // OHOS_OHAVSESSION_METADATA_H