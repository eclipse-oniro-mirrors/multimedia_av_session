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
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value
        {
            if (napiAVControllerCallback->sessionReleased_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->sessionReleased_callback_, &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv)
        {
            argc = 0;
        });
}

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGD("NapiAVControllerCallback::OnPlaybackStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value
        {
            if (napiAVControllerCallback->playbackStateChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->playbackStateChanged_callback_, &callback);
            return callback;
        },
        [&state](napi_env env, int& argc, napi_value* argv)
        {
            argc = 1;
            AVSessionNapiUtils::WrapAVPlaybackStateToNapi(env, state, argv[0]);
        });
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    SLOGD("NapiAVControllerCallback::OnMetaDataChange");
    bool isThrough = false;
    if (filterAVMetaDatas_.size() == 0) {
        isThrough = true;
    }
    for (size_t i = 0; i < filterAVMetaDatas_.size(); i++) {
        if (data.GetAssetId() == filterAVMetaDatas_[i].GetAssetId()) {
            isThrough = true;
        }
    }

    if (isThrough) {
        uvQueue_ = std::make_shared<UvQueue>(env_);
        uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value
        {
            if (napiAVControllerCallback->metaDataChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->metaDataChanged_callback_, &callback);
            return callback;
        },
        [&data](napi_env env, int& argc, napi_value* argv)
        {
            argc = 1;
            AVSessionNapiUtils::WrapAVMetadataToNapi(env, data, argv[0]);
        });
    }
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    SLOGD("NapiAVControllerCallback::OnActiveStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value
        {
            if (napiAVControllerCallback->activeStateChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->activeStateChanged_callback_, &callback);
            return callback;
        },
        [isActive](napi_env env, int& argc, napi_value* argv)
        {
            argc = 1;
            napi_get_boolean(env, isActive, &argv[0]);
        });
}

void NapiAVControllerCallback::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    SLOGD("NapiAVControllerCallback::OnValidCommandChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value
        {
            if (napiAVControllerCallback->validCommandChanged_callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, napiAVControllerCallback->validCommandChanged_callback_, &callback);
            return callback;
        },
        [&cmds](napi_env env, int& argc, napi_value* argv)
        {
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

void NapiAVControllerCallback::SaveFilter(const std::string& callbackName, napi_value filter, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK)) {
        SLOGE(" no native playbackStateChanged filter .");
    }
    if (!callbackName.compare(METADATACHANGED_CALLBACK)) {
        bool isArray = false;
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, filter, &valueType);
        if (valueType == napi_string) {
           std::string filterStr = AVSessionNapiUtils::GetStringArgument(env, filter);
           if (FILTER_ALL.compare(filterStr)) {
                filterAVMetaDatas_.resize(0);
           } else {
                SLOGE(" metadataChanged string filter Invalid .");
                return;
           }
        } else if (napi_is_array(env, filter, &isArray) == napi_ok && isArray) {
            uint32_t len = 0;
            napi_get_array_length(env, filter, &len);
            for (uint32_t i = 0; i < len; i++) {
                napi_value arrayData = nullptr;
                napi_get_element(env, filter, i, &arrayData);
                AVMetaData aVMetaData;
                AVSessionNapiUtils::WrapNapiToAVMetadata(env, filter, aVMetaData);
                filterAVMetaDatas_.push_back(aVMetaData);
            }
        } else {
            SLOGE(" metadataChanged Invalid filter ");
            return;
        }
    }
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