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

#include "OHAVMediaDescription.h"
#include "avmedia_description.h"
#include "avsession_log.h"

using namespace OHOS::AVSession;

OHAVMediaDescription::OHAVMediaDescription()
{
}

OHAVMediaDescription::~OHAVMediaDescription()
{
    if (mediaImage_ != nullptr) {
        delete mediaImage_;
        mediaImage_ = nullptr;
    }
}

AVQueueItem_Result OHAVMediaDescription::SetAssetId(const std::string &assetId)
{
    assetId_ = assetId;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetAssetId() const
{
    return assetId_;
}

AVQueueItem_Result OHAVMediaDescription::SetTitle(const std::string &title)
{
    title_ = title;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetTitle() const
{
    return title_;
}

AVQueueItem_Result OHAVMediaDescription::SetSubtitle(const std::string &subtitle)
{
    subtitle_ = subtitle;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetSubtitle() const
{
    return subtitle_;
}

AVQueueItem_Result OHAVMediaDescription::SetArtist(const std::string &artist)
{
    artist_ = artist;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetArtist() const
{
    return artist_;
}

AVQueueItem_Result OHAVMediaDescription::SetMediaImage(OH_PixelmapNative *mediaImage)
{
    mediaImage_ = mediaImage;
    return AVQUEUEITEM_SUCCESS;
}

OH_PixelmapNative* OHAVMediaDescription::GetMediaImage() const
{
    return mediaImage_;
}

AVQueueItem_Result OHAVMediaDescription::SetMediaType(const std::string &mediaType)
{
    mediaType_ = mediaType;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetMediaType() const
{
    return mediaType_;
}

AVQueueItem_Result OHAVMediaDescription::SetLyricContent(const std::string &lyricContent)
{
    lyricContent_ = lyricContent;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetLyricContent() const
{
    return lyricContent_;
}

AVQueueItem_Result OHAVMediaDescription::SetDuration(const int32_t duration)
{
    duration_ = duration;
    return AVQUEUEITEM_SUCCESS;
}

int32_t OHAVMediaDescription::GetDuration() const
{
    return duration_;
}

AVQueueItem_Result OHAVMediaDescription::SetMediaUri(const std::string &mediaUri)
{
    mediaUri_ = mediaUri;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetMediaUri() const
{
    return mediaUri_;
}

AVQueueItem_Result OHAVMediaDescription::SetStartPosition(const int32_t startPosition)
{
    startPosition_ = startPosition;
    return AVQUEUEITEM_SUCCESS;
}

int32_t OHAVMediaDescription::GetStartPosition() const
{
    return startPosition_;
}

AVQueueItem_Result OHAVMediaDescription::SetMediaSize(const int32_t mediaSize)
{
    mediaSize_ = mediaSize;
    return AVQUEUEITEM_SUCCESS;
}

int32_t OHAVMediaDescription::GetMediaSize() const
{
    return mediaSize_;
}

AVQueueItem_Result OHAVMediaDescription::SetAlbumTitle(const std::string &albumTitle)
{
    albumTitle_ = albumTitle;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetAlbumTitle() const
{
    return albumTitle_;
}

AVQueueItem_Result OHAVMediaDescription::SetAppName(const std::string &appName)
{
    appName_ = appName;
    return AVQUEUEITEM_SUCCESS;
}

const std::string& OHAVMediaDescription::GetAppName() const
{
    return appName_;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetAssetId(OH_AVSession_AVMediaDescription* description,
    char** assetId)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(assetId != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "assetId is null");
    *assetId = const_cast<char*>(((OHAVMediaDescription*)description)->GetAssetId().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetTitle(OH_AVSession_AVMediaDescription* description,
    char** title)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(title != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "title is null");
    *title = const_cast<char*>(((OHAVMediaDescription *)description)->GetTitle().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetSubtitle(OH_AVSession_AVMediaDescription* description,
    char** subtitle)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(subtitle != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "subtitle is null");
    *subtitle = const_cast<char*>(((OHAVMediaDescription *)description)->GetSubtitle().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetArtist(OH_AVSession_AVMediaDescription* description,
    char** artist)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(artist != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "artist is null");
    *artist = const_cast<char*>(((OHAVMediaDescription *)description)->GetArtist().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetMediaImage(OH_AVSession_AVMediaDescription* description,
    OH_PixelmapNative** pixelmap)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(pixelmap != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "pixelmap is null");
    *pixelmap = ((OHAVMediaDescription *)description)->GetMediaImage();
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetMediaType(OH_AVSession_AVMediaDescription* description,
    char** mediaType)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(mediaType != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaType is null");
    *mediaType = const_cast<char*>(((OHAVMediaDescription *)description)->GetMediaType().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetLyricContent(OH_AVSession_AVMediaDescription* description,
    char** lyricContent)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(lyricContent != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "lyricContent is null");
    *lyricContent = const_cast<char*>(((OHAVMediaDescription *)description)->GetLyricContent().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetDuration(OH_AVSession_AVMediaDescription* description,
    int32_t* duration)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(duration != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "duration is null");
    *duration = ((OHAVMediaDescription *)description)->GetDuration();
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetMediaUri(OH_AVSession_AVMediaDescription* description,
    char** mediaImageUri)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(mediaImageUri != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaImageUri is null");
    *mediaImageUri = const_cast<char*>(((OHAVMediaDescription *)description)->GetMediaUri().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetStartPosition(OH_AVSession_AVMediaDescription* description,
    int32_t* startPosition)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(startPosition != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "startPosition is null");
    *startPosition = ((OHAVMediaDescription *)description)->GetStartPosition();
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetMediaSize(OH_AVSession_AVMediaDescription* description,
    int32_t* mediaSize)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(mediaSize != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "mediaSize is null");
    *mediaSize = ((OHAVMediaDescription *)description)->GetMediaSize();
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetAlbumTitle(OH_AVSession_AVMediaDescription* description,
    char** albumTitle)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(albumTitle != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "albumTitle is null");
    *albumTitle = const_cast<char*>(((OHAVMediaDescription *)description)->GetAlbumTitle().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_GetAppName(OH_AVSession_AVMediaDescription* description,
    char** appName)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "description is null");
    CHECK_AND_RETURN_RET_LOG(appName != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM, "appName is null");
    *appName = const_cast<char*>(((OHAVMediaDescription *)description)->GetAppName().c_str());
    return AVQUEUEITEM_SUCCESS;
}

AVQueueItem_Result OH_AVSession_AVMediaDescription_Destroy(OH_AVSession_AVMediaDescription* avMediaDescription)
{
    CHECK_AND_RETURN_RET_LOG(avMediaDescription != nullptr, AVQUEUEITEM_ERROR_INVALID_PARAM,
        "avMediaDescription is null");
    OHOS::AVSession::OHAVMediaDescription *oh_avMediaDescription =
        (OHOS::AVSession::OHAVMediaDescription *)avMediaDescription;
    delete oh_avMediaDescription;
    oh_avMediaDescription = nullptr;
    return AVQUEUEITEM_SUCCESS;
}