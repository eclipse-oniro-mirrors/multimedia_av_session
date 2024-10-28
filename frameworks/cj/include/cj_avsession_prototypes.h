/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_CJ_AVSESSION_PROTOTYPES_H
#define OHOS_CJ_AVSESSION_PROTOTYPES_H

#include <cstdint>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* Value Type =====================*/
typedef struct {
    void* head;
    int64_t size;
} CArray;

typedef struct {
    int32_t kind;
    char* string;
    int64_t pixelMap;
} StringPixelMapParameter;

typedef struct {
    int32_t valueType;
    char* key;
    void* value;
    int64_t size;
} CParameters;

/* CangJie Struct =====================*/

typedef struct {
    int32_t state;
    bool muted;
} CAVCallState;

typedef struct {
    char* name;
    char* phoneNumber;
    int64_t avatar;
} CAVCallMetaData;

typedef struct {
    int64_t elapsedTime;
    int64_t updateTime;
} CPlaybackPosition;

typedef struct {
    int32_t state;
    double speed;
    CPlaybackPosition position;
    int64_t bufferedTime;
    int32_t loopMode;
    bool isFavorite;
    int32_t activeItemId;
    int32_t volume;
    int32_t maxVolume;
    bool muted;
    int32_t duration;
    int32_t videoWidth;
    int32_t videoHeight;
    CArray extras;
} CAVPlaybackState;

typedef struct {
    char* assetId;
    char* title;
    char* artist;
    char* author;
    char* avQueueName;
    char* avQueueId;
    StringPixelMapParameter avQueueImage;
    char* album;
    char* writer;
    char* composer;
    int64_t duration;
    StringPixelMapParameter mediaImage;
    int64_t publishDate;
    char* subtitle;
    char* description;
    char* lyric;
    char* previousAssetId;
    char* nextAssetId;
    int32_t filter;
    CArray drmSchemes;
    int32_t skipIntervals;
    int32_t displayTags;
    int32_t mediaLength;
    int32_t avQueueLength;
} CAVMetaData;

typedef struct {
    int32_t castCategory;
    int32_t deviceType;
    char* deviceId;
    char* deviceName;
    int32_t supportedProtocols;
    CArray supportedDrmCapabilities;
} CDeviceInfo;

typedef struct {
    CArray devices;
} COutputDeviceInfo;

typedef struct {
    int32_t fd;
    int64_t offset;
    int64_t length;
} CAVFileDescriptor;

typedef struct {
    int64_t fileSize;
    int64_t callback;
} CAVDataSrcDescriptor;

typedef struct {
    char* mediaId;
    char* title;
    char* subtitle;
    char* description;
    char* mediaUri;
    StringPixelMapParameter mediaImage;
    CArray extras;
    char* mediaType;
    int32_t mediaSize;
    char* albumTitle;
    char* albumCoverUri;
    char* lyricContent;
    char* lyricUri;
    char* artist;
    CAVFileDescriptor fdSrc;
    char* drmScheme;
    CAVDataSrcDescriptor dataSrc;
    int32_t duration;
    int32_t startPosition;
    int32_t creditsPosition;
    char* appName;
    int32_t displayTags;
} CAVMediaDescription;

typedef struct {
    int32_t itemId;
    CAVMediaDescription description;
} CAVQueueItem;

typedef struct {
    int32_t command;
    CParameters parameter;
} CAVControlCommand;


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* OHOS_CJ_AVSESSION_PROTOTYPES_H */