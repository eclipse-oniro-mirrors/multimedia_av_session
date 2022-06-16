/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "avsession_log.h"
#include "callback/napi_avcontroller_callback.h"

namespace OHOS::AVSession {
NapiAVControllerCallback::NapiAVControllerCallback()
{
    SLOGD("NapiAVControllerCallback::Constructor");
}

NapiAVControllerCallback::~NapiAVControllerCallback()
{
    SLOGD("NapiAVControllerCallback::Destructor");
}

void NapiAVControllerCallback::OnSessionDestroy()
{
    SLOGD("NapiAVControllerCallback::OnSessionDestroy");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->sessionReleased_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->sessionReleased_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {
            argc = 0;
        });
}

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGD("NapiAVControllerCallback::OnPlaybackStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->playbackStateChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->playbackStateChanged_callback_, &callback);
            return callback;
        },
        [&state](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapAVPlaybackStateToNapi(env, state, argv[0]);
        });
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    SLOGD("NapiAVControllerCallback::OnMetaDataChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->metaDataChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->metaDataChanged_callback_, &callback);
            return callback;
        },
        [&data](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            AVSessionNapiUtils::WrapAVMetadataToNapi(env, data, argv[0]);
        });
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    SLOGD("NapiAVControllerCallback::OnActiveStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->activeStateChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->activeStateChanged_callback_, &callback);
            return callback;
        },
        [isActive](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_get_boolean(env, isActive, &argv[0]);
        });
}

void NapiAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGD("NapiAVControllerCallback::OnValidCommandChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->validCommandChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->validCommandChanged_callback_, &callback);
            return callback;
        },
        [&cmds](napi_env env, int& argc, napi_value* argv) {
            argc = 1;
            napi_status status;
            size_t size = cmds.size();
            napi_create_array_with_length(env, size, &argv[0]);
            for (size_t i = 0; i < size; i ++) {
                napi_value valueParam = nullptr;
                (void)napi_create_object(env, &valueParam);
                int32_t cmd = cmds[i];
                if (aVControlCommandToStrMap.find(cmd) != aVControlCommandToStrMap.end()) {
                    napi_create_string_utf8(env, aVControlCommandToStrMap[cmd].c_str(),
                                            NAPI_AUTO_LENGTH, &valueParam);
                }
                status = napi_set_element(env, argv[0], i, valueParam);
                if (status != napi_ok) {
                    return ;
                }
            }
        });
}

void NapiAVControllerCallback::SaveCallbackReference(const std::string& callbackName,
                                                     napi_value callback,
                                                     napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    napi_status status = napi_create_reference(env, callback, refCount, &callbackRef);
    env_ = env;
    if (status == napi_ok) {
        if (!callbackName.compare(AVCONTROLLER_SESSIONRELEASED_CALLBACK)) {
            sessionReleased_callback_ = callbackRef;
        } else if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK)) {
            playbackStateChanged_callback_ = callbackRef;
        } else if (!callbackName.compare(METADATACHANGED_CALLBACK)) {
            metaDataChanged_callback_ = callbackRef;
        } else if (!callbackName.compare(ACTIVESTATECHANGED_CALLBACK)) {
            activeStateChanged_callback_ = callbackRef;
        } else if (!callbackName.compare(VALIDCOMMANDCHANGED_CALLBACK)) {
            validCommandChanged_callback_ = callbackRef;
        } else if (!callbackName.compare(AVCONTROLLER_OUTPUTDEVICECHANGED_CALLBACK)) {
            outputDeviceChanged_callback_ = callbackRef;
        }
    }
}

#define CHECK_AND_SET_MASK(env, arrayData, propertyName, res, mask)                   \
    do {                                                                              \
        if (napi_get_named_property(env, arrayData, propertyName, &res) == napi_ok) { \
            metaMaskType.set((mask));                                                 \
        }                                                                             \
    } while (0)

void NapiAVControllerCallback::SaveFilter(std::shared_ptr<AVSessionController>& avsessionController,
                                          const std::string& callbackName,
                                          napi_value filter,
                                          napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(avsessionController != nullptr, "avsessionController is nullptr");
    CHECK_AND_RETURN_LOG(callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK), "no playbackStateChanged filter");
    CHECK_AND_RETURN_LOG(callbackName.compare(METADATACHANGED_CALLBACK), "no metadataChange filter");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, filter, &valueType);
    AVMetaData::MetaMaskType metaMaskType;
    if (valueType == napi_string) {
        std::string filterStr = AVSessionNapiUtils::GetStringArgument(env, filter);
        CHECK_AND_RETURN_LOG(FILTER_ALL.compare(filterStr) == 0, "metadataChanged string filter Invalid .");
        metaMaskType.set();
        avsessionController->SetMetaFilter(metaMaskType);
        return;
    }
    bool isArray = false;
    CHECK_AND_RETURN_LOG((napi_is_array(env, filter, &isArray) == napi_ok && isArray), "array is error");
    uint32_t arrayLength = 0;
    napi_get_array_length(env, filter, &arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value arrayData = nullptr;
        napi_value res = nullptr;
        napi_get_element(env, filter, i, &arrayData);
        CHECK_AND_SET_MASK(env, arrayData, "assetId", res, AVMetaData::META_KEY_ASSET_ID);
        CHECK_AND_SET_MASK(env, arrayData, "title", res, AVMetaData::META_KEY_TITLE);
        CHECK_AND_SET_MASK(env, arrayData, "artist", res, AVMetaData::META_KEY_ARTIST);
        CHECK_AND_SET_MASK(env, arrayData, "author", res, AVMetaData::META_KEY_AUTHOR);
        CHECK_AND_SET_MASK(env, arrayData, "album", res, AVMetaData::META_KEY_ALBUM);
        CHECK_AND_SET_MASK(env, arrayData, "writer", res, AVMetaData::META_KEY_WRITER);
        CHECK_AND_SET_MASK(env, arrayData, "composer", res, AVMetaData::META_KEY_COMPOSER);
        CHECK_AND_SET_MASK(env, arrayData, "duration", res, AVMetaData::META_KEY_DURATION);
        CHECK_AND_SET_MASK(env, arrayData, "publishDate", res, AVMetaData::META_KEY_PUBLISH_DATE);
        CHECK_AND_SET_MASK(env, arrayData, "subtitle", res, AVMetaData::META_KEY_SUBTITLE);
        CHECK_AND_SET_MASK(env, arrayData, "description", res, AVMetaData::META_KEY_DESCRIPTION);
        CHECK_AND_SET_MASK(env, arrayData, "lyric", res, AVMetaData::META_KEY_LYRIC);
        CHECK_AND_SET_MASK(env, arrayData, "previousAssetId", res, AVMetaData::META_KEY_PREVIOUS_ASSET_ID);
        CHECK_AND_SET_MASK(env, arrayData, "nextAssetId", res, AVMetaData::META_KEY_NEXT_ASSET_ID);
        if (napi_get_named_property(env, arrayData, "mediaImage", &res) == napi_ok) {
            napi_typeof(env, res, &valueType);
            if (valueType == napi_string) {
                metaMaskType.set(AVMetaData::META_KEY_MEDIA_IMAGE_URI);
            } else {
                metaMaskType.set(AVMetaData::META_KEY_MEDIA_IMAGE);
            }
        }
    }
    avsessionController->SetMetaFilter(metaMaskType);
}

void NapiAVControllerCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callbackName.compare(AVCONTROLLER_SESSIONRELEASED_CALLBACK)) {
        sessionReleased_callback_ = nullptr;
    } else if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK)) {
        playbackStateChanged_callback_ = nullptr;
    } else if (!callbackName.compare(METADATACHANGED_CALLBACK)) {
        metaDataChanged_callback_ = nullptr;
    } else if (!callbackName.compare(ACTIVESTATECHANGED_CALLBACK)) {
        activeStateChanged_callback_ = nullptr;
    } else if (!callbackName.compare(AVCONTROLLER_OUTPUTDEVICECHANGED_CALLBACK)) {
        outputDeviceChanged_callback_ = nullptr;
    }
}
}