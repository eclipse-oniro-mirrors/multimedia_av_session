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
#include "OHAVMetadataBuilder.h"
#include "avmeta_data.h"
#include "avsession_log.h"

using namespace OHOS::AVSession;

AVMetadata_Result OHAVMetadataBuilder::SetTitle(const std::string &title)
{
    title_ = title;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetArtist(const std::string &artist)
{
    artist_ = artist;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetAuthor(const std::string &author)
{
    author_ = author;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetAlbum(const std::string &album)
{
    album_ = album;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetWriter(const std::string &writer)
{
    writer_ = writer;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetComposer(const std::string &composer)
{
    composer_ = composer;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetDuration(int64_t duration)
{
    duration_ = duration;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetMediaImageUri(const std::string &mediaImageUri)
{
    mediaImageUri_ = mediaImageUri;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetSubtitle(const std::string &subtitle)
{
    subtitle_ = subtitle;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetDescription(const std::string &description)
{
    description_ = description;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetLyric(const std::string &lyric)
{
    lyric_ = lyric;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetAssetId(const std::string &assetId)
{
    assetId_ = assetId;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetPreviousAssetId(const std::string &assetId)
{
    previousAssetId_ = assetId;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetNextAssetId(const std::string &assetId)
{
    nextAssetId_ = assetId;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::SetSkipIntervals(AVMetadata_SkipIntervals intervals)
{
    switch (intervals) {
        case SECONDS_10:
        case SECONDS_15:
        case SECONDS_30:
            intervals_ = intervals;
            return AVMETADATA_SUCCESS;
        default:
            SLOGE("Failed to set skip intervals: Invalid skip intervals value: %d", intervals);
            return AVMETADATA_ERROR_INVALID_PARAM;
    }
}

AVMetadata_Result OHAVMetadataBuilder::SetDisplayTags(int32_t tags)
{
    tags_ = tags;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OHAVMetadataBuilder::GenerateAVMetadata(OH_AVMetadata** avMetadata)
{
    CHECK_AND_RETURN_RET_LOG(avMetadata != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "avMetadata is null");

    AVMetaData* metaData = new AVMetaData();
    if (metaData == nullptr) {
        SLOGE("Failed to allocate memory for AVMetaData");
        *avMetadata = nullptr;
        return AVMETADATA_ERROR_NO_MEMORY;
    }

    switch (intervals_) {
        case SECONDS_10:
            metaData->SetSkipIntervals(AVMetaData::SECONDS_10);
            break;
        case SECONDS_15:
            metaData->SetSkipIntervals(AVMetaData::SECONDS_15);
            break;
        case SECONDS_30:
            metaData->SetSkipIntervals(AVMetaData::SECONDS_30);
            break;
        default:
            SLOGE("Failed to generate avMetadata: Unsupported skip intervals: %d", intervals_);
            delete metaData;
            *avMetadata = nullptr;
            return AVMETADATA_ERROR_INVALID_PARAM;
    }

    metaData->SetTitle(title_);
    metaData->SetArtist(artist_);
    metaData->SetAuthor(author_);
    metaData->SetAlbum(album_);
    metaData->SetWriter(writer_);
    metaData->SetComposer(composer_);
    metaData->SetDuration(duration_);
    metaData->SetMediaImageUri(mediaImageUri_);
    metaData->SetSubTitle(subtitle_);
    metaData->SetDescription(description_);
    metaData->SetLyric(lyric_);
    metaData->SetAssetId(assetId_);
    metaData->SetPreviousAssetId(previousAssetId_);
    metaData->SetNextAssetId(nextAssetId_);
    metaData->SetDisplayTags(tags_);

    *avMetadata = reinterpret_cast<OH_AVMetadata*>(metaData);

    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OH_AVMetadataBuilder_Create(OH_AVMetadataBuilder** builder)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");

    OHAVMetadataBuilder* metadata = new OHAVMetadataBuilder();
    if (metadata == nullptr) {
        SLOGE("Failed to allocate memory for OHAVMetadataBuilder");
        return AVMETADATA_ERROR_NO_MEMORY;
    }

    *builder = reinterpret_cast<OH_AVMetadataBuilder*>(metadata);
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OH_AVMetadataBuilder_Destroy(OH_AVMetadataBuilder* builder)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    delete metadata;
    return AVMETADATA_SUCCESS;
}

AVMetadata_Result OH_AVMetadataBuilder_SetTitle(OH_AVMetadataBuilder* builder, const char* title)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetTitle(title);
}

AVMetadata_Result OH_AVMetadataBuilder_SetArtist(OH_AVMetadataBuilder* builder, const char* artist)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetArtist(artist);
}

AVMetadata_Result OH_AVMetadataBuilder_SetAuthor(OH_AVMetadataBuilder* builder, const char* author)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetAuthor(author);
}

AVMetadata_Result OH_AVMetadataBuilder_SetAlbum(OH_AVMetadataBuilder* builder, const char* album)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetAlbum(album);
}

AVMetadata_Result OH_AVMetadataBuilder_SetWriter(OH_AVMetadataBuilder* builder, const char* writer)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetWriter(writer);
}

AVMetadata_Result OH_AVMetadataBuilder_SetComposer(OH_AVMetadataBuilder* builder, const char* composer)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetComposer(composer);
}

AVMetadata_Result OH_AVMetadataBuilder_SetDuration(OH_AVMetadataBuilder* builder, int64_t duration)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetDuration(duration);
}

AVMetadata_Result OH_AVMetadataBuilder_SetMediaImageUri(OH_AVMetadataBuilder* builder, const char* mediaImageUri)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetMediaImageUri(mediaImageUri);
}

AVMetadata_Result OH_AVMetadataBuilder_SetSubtitle(OH_AVMetadataBuilder* builder, const char* subtitle)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetSubtitle(subtitle);
}

AVMetadata_Result OH_AVMetadataBuilder_SetDescription(OH_AVMetadataBuilder* builder, const char* description)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetDescription(description);
}

AVMetadata_Result OH_AVMetadataBuilder_SetLyric(OH_AVMetadataBuilder* builder, const char* lyric)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetLyric(lyric);
}

AVMetadata_Result OH_AVMetadataBuilder_SetAssetId(OH_AVMetadataBuilder* builder, const char* assetId)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetAssetId(assetId);
}

AVMetadata_Result OH_AVMetadataBuilder_SetPreviousAssetId(OH_AVMetadataBuilder* builder, const char* assetId)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetPreviousAssetId(assetId);
}

AVMetadata_Result OH_AVMetadataBuilder_SetNextAssetId(OH_AVMetadataBuilder* builder, const char* assetId)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetNextAssetId(assetId);
}

AVMetadata_Result OH_AVMetadataBuilder_SetSkipIntervals(OH_AVMetadataBuilder* builder,
                                                        AVMetadata_SkipIntervals intervals)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetSkipIntervals(intervals);
}

AVMetadata_Result OH_AVMetadataBuilder_SetDisplayTags(OH_AVMetadataBuilder* builder, uint32_t tags)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->SetDisplayTags(tags);
}

AVMetadata_Result OH_AVMetadataBuilder_GenerateAVMetadata(OH_AVMetadataBuilder* builder,
                                                          OH_AVMetadata** avMetadata)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(avMetadata != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "avMetadata is null");
    OHAVMetadataBuilder* metadata = reinterpret_cast<OHAVMetadataBuilder*>(builder);
    return metadata->GenerateAVMetadata(avMetadata);
}

AVMetadata_Result OH_AVMetadata_Destory(OH_AVMetadata* avMetadata)
{
    CHECK_AND_RETURN_RET_LOG(avMetadata != nullptr, AVMETADATA_ERROR_INVALID_PARAM, "avMetadata is null");
    AVMetaData* metadata = reinterpret_cast<AVMetaData*>(avMetadata);
    delete metadata;
    return AVMETADATA_SUCCESS;
}