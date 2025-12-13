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
#include "OHAVMediaDescriptionBuilder.h"
#include "avsession_log.h"
#include "OHAVMediaDescription.h"

using namespace OHOS::AVSession;

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetAssetId(const std::string &assetId)
{
    assetId_ = assetId;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetTitle(const std::string &title)
{
    title_ = title;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetSubtitle(const std::string &subtitle)
{
    subtitle_ = subtitle;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetArtist(const std::string &artist)
{
    artist_ = artist;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetMediaImage(OH_PixelmapNative *mediaImage)
{
    mediaImage_ = mediaImage;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetMediaType(const std::string &mediaType)
{
    mediaType_ = mediaType;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetLyricContent(const std::string &lyricContent)
{
    lyricContent_ = lyricContent;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetDuration(const int32_t duration)
{
    duration_ = duration;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetMediaUri(const std::string &mediaUri)
{
    mediaUri_ = mediaUri;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetStartPosition(const int32_t startPosition)
{
    startPosition_ = startPosition;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetMediaSize(const int32_t mediaSize)
{
    mediaSize_ = mediaSize;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetAlbumTitle(const std::string &albumTitle)
{
    albumTitle_ = albumTitle;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::SetAppName(const std::string &appName)
{
    appName_ = appName;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OHAVMediaDescriptionBuilder::GenerateAVMediaDescription(OHAVMediaDescription** avMediaDescription)
{
    CHECK_AND_RETURN_RET_LOG(avMediaDescription != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM,
        "avMediaDescription is null");
    *avMediaDescription = new OHAVMediaDescription();
    if (*avMediaDescription == nullptr) {
        SLOGE("Failed to allocate memory for OHAVMediaDescription");
        return AVQUEUEITEM_ERROR_NO_MEMORY;
    }
    (*avMediaDescription)->SetAssetId(assetId_);
    (*avMediaDescription)->SetTitle(title_);
    (*avMediaDescription)->SetSubtitle(subtitle_);
    (*avMediaDescription)->SetArtist(artist_);
    (*avMediaDescription)->SetMediaImage(mediaImage_);
    (*avMediaDescription)->SetMediaType(mediaType_);
    (*avMediaDescription)->SetLyricContent(lyricContent_);
    (*avMediaDescription)->SetDuration(duration_);
    (*avMediaDescription)->SetMediaUri(mediaUri_);
    (*avMediaDescription)->SetStartPosition(startPosition_);
    (*avMediaDescription)->SetMediaSize(mediaSize_);
    (*avMediaDescription)->SetAlbumTitle(albumTitle_);
    (*avMediaDescription)->SetAppName(appName_);

    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_Create(OH_AVSession_AVMediaDescriptionBuilder** builder)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");

    OHAVMediaDescriptionBuilder* mediaDescription = new OHAVMediaDescriptionBuilder();
    if (mediaDescription == nullptr) {
        SLOGE("Failed to allocate memory for OHAVMediaDescriptionBuilder");
        return AVQUEUEITEM_ERROR_NO_MEMORY;
    }
    *builder = reinterpret_cast<OH_AVSession_AVMediaDescriptionBuilder*>(mediaDescription);
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_Destroy(OH_AVSession_AVMediaDescriptionBuilder* builder)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    delete mediaDescriptionBuilder;
    mediaDescriptionBuilder = nullptr;
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetAssetId(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* assetId)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(assetId != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "assetId is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set assetId: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetAssetId(assetId);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetTitle(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* title)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(title != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "title is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set title: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetTitle(title);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetSubTitle(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* subtitle)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(subtitle != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "subtitle is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set subtitle: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetSubtitle(subtitle);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetArtist(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* artist)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(artist != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "artist is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set artist: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetArtist(artist);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetMediaImage(OH_AVSession_AVMediaDescriptionBuilder* builder,
    OH_PixelmapNative *mediaImage)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(mediaImage != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaImage is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set mediaImage: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetMediaImage(mediaImage);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetMediaType(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* mediaType)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(mediaType != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaType is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set mediaType: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetMediaType(mediaType);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetLyricContent(
    OH_AVSession_AVMediaDescriptionBuilder* builder, const char* lyricContent)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(lyricContent != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "lyricContent is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set lyricContent: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetLyricContent(lyricContent);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetDuration(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const int32_t duration)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(duration >= 0, AVQUEUEITEM_ERROR_INVALID_PARAM, "duration is invalid");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set duration: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetDuration(duration);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetMediaUri(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* mediaUri)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(mediaUri != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaUri is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set mediaUri: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetMediaUri(mediaUri);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetStartPosition(
    OH_AVSession_AVMediaDescriptionBuilder* builder, const int32_t startPosition)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(startPosition >= 0, AVQUEUEITEM_ERROR_INVALID_PARAM, "startPosition is invalid");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set startPosition: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetStartPosition(startPosition);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetMediaSize(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const int32_t mediaSize)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(mediaSize >= 0, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaSize is invalid");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set mediaSize: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetMediaSize(mediaSize);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetAlbumTitle(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* albumTitle)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(albumTitle != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "albumTitle is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set albumTitle: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetAlbumTitle(albumTitle);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_SetAppName(OH_AVSession_AVMediaDescriptionBuilder* builder,
    const char* appName)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(appName != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "appName is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to set appName: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->SetAppName(appName);
}

AVQueueItem_Result OH_AVSession_AVMediaDescriptionBuilder_GenerateAVMediaDescription(
    OH_AVSession_AVMediaDescriptionBuilder* builder, OH_AVSession_AVMediaDescription** avMediaDescription)
{
    CHECK_AND_RETURN_RET_LOG(builder != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "builder is null");
    CHECK_AND_RETURN_RET_LOG(avMediaDescription != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM,
        "avMediaDescription is null");
    OHAVMediaDescriptionBuilder* mediaDescriptionBuilder = reinterpret_cast<OHAVMediaDescriptionBuilder*>(builder);
    if (mediaDescriptionBuilder == nullptr) {
        SLOGE("Failed to generate AvMediaDescription: mediaDescriptionBuilder is null");
        return AVQUEUEITEM_ERROR_INVALID_PARAM;
    }
    return mediaDescriptionBuilder->GenerateAVMediaDescription((OHAVMediaDescription **)avMediaDescription);
}