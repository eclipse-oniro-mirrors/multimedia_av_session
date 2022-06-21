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
    SLOGI("NapiAVControllerCallback::Constructor");
}

NapiAVControllerCallback::~NapiAVControllerCallback()
{
    SLOGI("NapiAVControllerCallback::Destructor");
}

void NapiAVControllerCallback::OnSessionDestroy()
{
    SLOGI("NapiAVControllerCallback::OnSessionDestroy");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->bindCallbackMap[AVCONTROLLER_SESSIONRELEASED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiAVControllerCallback->bindCallbackMap[AVCONTROLLER_SESSIONRELEASED_CALLBACK],
                                     &callback);
            return callback;
        },
        [](napi_env env, int& argc, napi_value* argv) {});
}

void NapiAVControllerCallback::OnPlaybackStateChange(const AVPlaybackState& state)
{
    SLOGI("NapiAVControllerCallback::OnPlaybackStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    aVPlaybackState_ = std::make_shared<AVPlaybackState>();
    aVPlaybackState_->SetState(state.GetState());
    aVPlaybackState_->SetSpeed(state.GetSpeed());
    aVPlaybackState_->SetUpdateTime(state.GetUpdateTime());
    aVPlaybackState_->SetElapsedTime(state.GetElapsedTime());
    aVPlaybackState_->SetBufferedTime(state.GetBufferedTime());
    aVPlaybackState_->SetLoopMode(state.GetLoopMode());
    aVPlaybackState_->SetFavorite(state.GetFavorite());
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->bindCallbackMap[PLAYBACKSTATECHANGED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiAVControllerCallback->bindCallbackMap[PLAYBACKSTATECHANGED_CALLBACK],
                                     &callback);
            return callback;
        },
        [napiAVControllerCallback = shared_from_this()](napi_env env, int& argc, napi_value* argv) {
            if (napiAVControllerCallback->aVPlaybackState_ == nullptr) {
                SLOGE("OnPlaybackStateChange AVPlaybackState is nullptr");
                return;
            }
            argc = 1;
            AVSessionNapiUtils::WrapAVPlaybackStateToNapi(env, *napiAVControllerCallback->aVPlaybackState_, argv[0]);
        });
}

void NapiAVControllerCallback::OnMetaDataChange(const AVMetaData& data)
{
    SLOGI("NapiAVControllerCallback::OnMetaDataChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    aVMetaData_ = std::make_shared<AVMetaData>();
    aVMetaData_->CopyFrom(data);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->bindCallbackMap[METADATACHANGED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiAVControllerCallback->bindCallbackMap[METADATACHANGED_CALLBACK],
                                     &callback);
            return callback;
        },
        [napiAVControllerCallback = shared_from_this()](napi_env env, int& argc, napi_value* argv) {
            if (napiAVControllerCallback->aVMetaData_ == nullptr) {
                SLOGE("OnMetaDataChange AVMetaData is nullptr");
                return;
            }
            argc = 1;
            AVSessionNapiUtils::WrapAVMetadataToNapi(env, *napiAVControllerCallback->aVMetaData_, argv[0]);
        });
}

void NapiAVControllerCallback::OnActiveStateChange(bool isActive)
{
    SLOGI("NapiAVControllerCallback::OnActiveStateChange");
    uvQueue_ = std::make_shared<UvQueue>(env_);
    uvQueue_->AsyncCall(
        [napiAVControllerCallback = shared_from_this()](napi_env env) -> napi_value {
            if (napiAVControllerCallback->bindCallbackMap[ACTIVESTATECHANGED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiAVControllerCallback->bindCallbackMap[ACTIVESTATECHANGED_CALLBACK],
                                     &callback);
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
            if (napiAVControllerCallback->bindCallbackMap[VALIDCOMMANDCHANGED_CALLBACK] == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env,
                                     napiAVControllerCallback->bindCallbackMap[VALIDCOMMANDCHANGED_CALLBACK],
                                     &callback);
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

void NapiAVControllerCallback::SaveCallbackReference(const std::string& callbackName, napi_value args, napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    napi_ref callback = nullptr;
    napi_status status = napi_create_reference(env, args, 1, &callback);
    env_ = env;
    CHECK_AND_RETURN_LOG(status == napi_ok && callback != nullptr, "get callback fail ");
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    bindCallbackMap[callbackName] = callback ;
}

void NapiAVControllerCallback::ReleaseCallbackReference(const std::string& callbackName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(bindCallbackMap.count(callbackName) != 0, "The callbackName parameter is invalid ");
    napi_delete_reference(env_, bindCallbackMap[callbackName]);
}

bool NapiAVControllerCallback::hasCallback(const std::string& callbackName)
{
    return bindCallbackMap.count(callbackName) != 0 ;
}

void NapiAVControllerCallback::SaveFilter(std::shared_ptr<AVSessionController>& avsessionController,
                                          const std::string& callbackName,
                                          napi_value filter,
                                          napi_env env)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(avsessionController != nullptr, "avsessionController is nullptr");
    if (!callbackName.compare(PLAYBACKSTATECHANGED_CALLBACK)) {
        SetPlaybackStateFilter(avsessionController, filter, env);
    } else if (!callbackName.compare(METADATACHANGED_CALLBACK)) {
        SetMetaFilter(avsessionController, filter, env);
    }
}

void NapiAVControllerCallback::SetPlaybackStateFilter(std::shared_ptr<AVSessionController>& avsessionController,
                                                      napi_value filter,
                                                      napi_env env)
{
    CHECK_AND_RETURN_LOG(false, "playbackStateChange no filter method for now");
}

void NapiAVControllerCallback::SetMetaFilter(std::shared_ptr<AVSessionController>& avsessionController,
                                             napi_value filter,
                                             napi_env env)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, filter, &valueType);
    AVMetaData::MetaMaskType metaMaskType;
    if (valueType == napi_string) {
        std::string filterStr = AVSessionNapiUtils::GetStringArgument(env, filter);
        CHECK_AND_RETURN_LOG(!FILTER_ALL.compare(filterStr), "string filter Only support all");
        GenerateAllMetaMaskType(metaMaskType);
        avsessionController->SetMetaFilter(metaMaskType);
        return;
    }
    bool isArray = false;
    CHECK_AND_RETURN_LOG((napi_is_array(env, filter, &isArray) == napi_ok && isArray), "array is error");
    uint32_t arrayLength = 0;
    napi_get_array_length(env, filter, &arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value napiMetaData = nullptr;
        napi_get_element(env, filter, i, &napiMetaData);
        SetMetaMaskTypeByNapi(metaMaskType, napiMetaData, env);
    }
    avsessionController->SetMetaFilter(metaMaskType);
}

void NapiAVControllerCallback::GenerateAllMetaMaskType(AVMetaData::MetaMaskType& metaMaskType)
{
    for (int8_t i = AVMetaData::META_KEY_ASSET_ID; i < AVMetaData::META_KEY_MAX; i++) {
        metaMaskType.set(i);
    }
}

void NapiAVControllerCallback::SetMetaMaskTypeByNapi(AVMetaData::MetaMaskType& metaMaskType,
                                                     napi_value napiMetaData,
                                                     napi_env env)
{
    bool hasProperty = false;
    std::map<std::string, int32_t>::reverse_iterator   iter;
    for (iter = aVMetaDataMap.rbegin(); iter != aVMetaDataMap.rend(); iter++) {
        if (napi_has_named_property(env, napiMetaData, iter->first.c_str(), &hasProperty) == napi_ok && hasProperty) {
            metaMaskType.set(iter->second);
        }
    }

    napi_value res = nullptr;
    if (napi_get_named_property(env, napiMetaData, "mediaImage", &res) == napi_ok) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, res, &valueType);
        if (valueType == napi_string) {
            metaMaskType.set(AVMetaData::META_KEY_MEDIA_IMAGE_URI);
        } else {
            metaMaskType.set(AVMetaData::META_KEY_MEDIA_IMAGE);
        }
    }
}
}