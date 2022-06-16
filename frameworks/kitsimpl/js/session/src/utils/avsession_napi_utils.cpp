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

#include "utils/avsession_napi_utils.h"

namespace OHOS::AVSession {
napi_status AVSessionNapiUtils::CreateJSObject(napi_env env,
                                               napi_value exports,
                                               std::string className,
                                               napi_callback callback,
                                               napi_property_descriptor* properties,
                                               size_t propertyCount,
                                               napi_ref* result)
{
    napi_status status;
    napi_value constructor;
    const int32_t refCount = 1;

    status = napi_define_class(env,
                               className.c_str(),
                               NAPI_AUTO_LENGTH,
                               callback,
                               nullptr,
                               propertyCount,
                               properties,
                               &constructor);

    if (status == napi_ok) {
        status = napi_create_reference(env, constructor, refCount, result);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, className.c_str(), constructor);
            if (status == napi_ok) {
                return status;
            }
        }
    }
    return napi_closing;
}

napi_value AVSessionNapiUtils::NapiUndefined(napi_env env)
{
    napi_value undefinedResult = nullptr;
    napi_get_undefined(env, &undefinedResult);
    return undefinedResult;
}

napi_value AVSessionNapiUtils::CreateNapiString(napi_env env, std::string str)
{
    napi_value napiStr = nullptr;
    napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &napiStr);
    return napiStr;
}

napi_status AVSessionNapiUtils::SetValueInt32(const napi_env& env, const std::string& fieldStr,
                                              const int32_t intValue, napi_value& result)
{
    napi_status status;
    napi_value value = nullptr;
    status = napi_create_int32(env, intValue, &value);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    }
    return status;
}

napi_status AVSessionNapiUtils::SetValueInt64(const napi_env& env, const std::string& fieldStr,
                                              const int64_t intValue, napi_value& result)
{
    napi_status status;
    napi_value value = nullptr;
    status = napi_create_int64(env, intValue, &value);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    }
    return status;
}

napi_status AVSessionNapiUtils::SetValueString(const napi_env& env, const std::string& fieldStr,
                                               const std::string& stringValue, napi_value& result)
{
    napi_status status;
    status = napi_set_named_property(env, result, fieldStr.c_str(),
                                     AVSessionNapiUtils::CreateNapiString(env, stringValue));
    return status;
}

napi_status AVSessionNapiUtils::SetValueBool(const napi_env& env, const std::string& fieldStr,
                                             const bool &boolValue, napi_value& result)
{
    napi_status status;
    napi_value value = nullptr;
    status = napi_get_boolean(env, boolValue, &value);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    }
    return status;
}

int32_t AVSessionNapiUtils::GetValueInt32(const napi_env& env, const std::string& fieldStr, const napi_value& value)
{
    napi_value res = nullptr;
    int32_t result = 0;
    if (napi_get_named_property(env, value, fieldStr.c_str(), &res) == napi_ok) {
        napi_get_value_int32(env, res, &result);
    }
    return result;
}

bool AVSessionNapiUtils::GetValueBool(const napi_env& env, const std::string& fieldStr, const napi_value& value)
{
    napi_value res = nullptr;
    bool result = false;
    if (napi_get_named_property(env, value, fieldStr.c_str(), &res) == napi_ok) {
        napi_get_value_bool(env, res, &result);
    }
    return result;
}

std::string AVSessionNapiUtils::GetValueString(const napi_env& env,
                                               const std::string& fieldStr,
                                               const napi_value& value)
{
    napi_value res = nullptr;
    std::string result = "";
    if (napi_get_named_property(env, value, fieldStr.c_str(), &res) == napi_ok) {
        result =  GetStringArgument(env, res);
    }
    return result;
}

napi_value AVSessionNapiUtils::WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

std::string AVSessionNapiUtils::GetSessionType(const int32_t type)
{
    if (type == AVSession::SESSION_TYPE_AUDIO) {
        return "audio";
    }
    if (type == AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    }
    return "";
}

std::string AVSessionNapiUtils::GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &bufLength);
    if (status == napi_ok && bufLength > 0 && bufLength < PATH_MAX) {
        char* buffer = (char*)malloc((bufLength + 1) * sizeof(char));
        CHECK_AND_RETURN_RET_LOG(buffer != nullptr, strValue, "no memory");
        status = napi_get_value_string_utf8(env, value, buffer, bufLength + 1, &bufLength);
        if (status == napi_ok) {
            SLOGI("argument = %{public}s", buffer);
            strValue = buffer;
        }
        free(buffer);
        buffer = nullptr;
    }
    return strValue;
}

napi_status AVSessionNapiUtils::SetValueDouble(const napi_env& env, const std::string& fieldStr,
                                               const double doubleValue, napi_value& result)
{
    napi_status status;
    napi_value value = nullptr;
    status = napi_create_double(env, doubleValue, &value);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    }
    return status;
}

double AVSessionNapiUtils::GetValueDouble(const napi_env& env, const std::string& fieldStr, const napi_value& value)
{
    napi_value res = nullptr;
    double result = 0;
    if (napi_get_named_property(env, value, fieldStr.c_str(), &res) == napi_ok) {
        napi_get_value_double(env, res, &result);
    }
    return result;
}

void AVSessionNapiUtils::WrapNapiToAVMetadata(napi_env env, napi_value object, AVMetaData& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        std::string assetId = AVSessionNapiUtils::GetValueString(env, "assetId", object);
        if (assetId.empty()) {
            SLOGE("AVMetaData get param assetId  fail ");
            return;
        }

        result.SetAssetId(assetId);
        napi_value res = nullptr;
        if (napi_get_named_property(env, object, "title", &res) == napi_ok) {
            std::string title = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetTitle(title);
        }
        if (napi_get_named_property(env, object, "artist", &res) == napi_ok) {
            std::string artist = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetArtist(artist);
        }

        if (napi_get_named_property(env, object, "author", &res) == napi_ok) {
            std::string author = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetAuthor(author);
        }
        if (napi_get_named_property(env, object, "album", &res) == napi_ok) {
            std::string album = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetAlbum(album);
        }
        if (napi_get_named_property(env, object, "writer", &res) == napi_ok) {
            std::string writer = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetWriter(writer);
        }
        if (napi_get_named_property(env, object, "composer", &res) == napi_ok) {
            std::string composer = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetComposer(composer);
        }
        if (napi_get_named_property(env, object, "duration", &res) == napi_ok) {
            int64_t duration = 0;
            napi_get_value_int64(env, res, &duration);
            result.SetDuration(duration);
        }
        if (napi_get_named_property(env, object, "mediaImage", &res) == napi_ok) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, res, &valueType);

            if (valueType == napi_string) {
                std::string mediaImageUri = AVSessionNapiUtils::GetStringArgument(env, res);
                result.SetMediaImageUri(mediaImageUri);
            } else {
                std::shared_ptr<Media::PixelMap> mediaImage = nullptr;
                napi_status status = napi_unwrap(env, res, (void**)&mediaImage);
                if (status != napi_ok || mediaImage == nullptr) {
                    SLOGE("napi_unwrap mediaImage error");
                }
                result.SetMediaImage(mediaImage);
            }
        }

        if (napi_get_named_property(env, object, "publishDate", &res) == napi_ok) {
            double date = 0.0f;
            napi_get_date_value(env, res, &date);
            result.SetPublishDate(date);
        }

        if (napi_get_named_property(env, object, "subtitle", &res) == napi_ok) {
            std::string subtitle = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetSubTitle(subtitle);
        }

        if (napi_get_named_property(env, object, "description", &res) == napi_ok) {
            std::string description = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetDescription(description);
        }

        if (napi_get_named_property(env, object, "lyric", &res) == napi_ok) {
            std::string lyric = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetLyric(lyric);
        }

        if (napi_get_named_property(env, object, "previousAssetId", &res) == napi_ok) {
            std::string previousAssetId = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetPreviosAssetId(previousAssetId);
        }
        if (napi_get_named_property(env, object, "nextAssetId", &res) == napi_ok) {
            std::string nextAssetId = AVSessionNapiUtils::GetStringArgument(env, res);
            result.SetNextAssetId(nextAssetId);
        }
    }
}

void AVSessionNapiUtils::WrapAVMetadataToNapi(napi_env env, const AVMetaData& aVMetaData, napi_value& result)
{
    napi_create_object(env, &result);
    AVSessionNapiUtils::SetValueString(env, "assetId", aVMetaData.GetAssetId(), result);
    AVSessionNapiUtils::SetValueString(env, "title", aVMetaData.GetTitle(), result);
    AVSessionNapiUtils::SetValueString(env, "artist", aVMetaData.GetArtist(), result);
    AVSessionNapiUtils::SetValueString(env, "author", aVMetaData.GetAuthor(), result);
    AVSessionNapiUtils::SetValueString(env, "album", aVMetaData.GetAlbum(), result);
    AVSessionNapiUtils::SetValueString(env, "writer", aVMetaData.GetWriter(), result);
    AVSessionNapiUtils::SetValueString(env, "composer", aVMetaData.GetComposer(), result);
    AVSessionNapiUtils::SetValueInt64(env, "duration", aVMetaData.GetDuration(), result);



    napi_value publishDateValue = nullptr;
    napi_status status = napi_create_date(env,
        aVMetaData.GetPublishDate(), &publishDateValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, "publishDate", publishDateValue);
    }

    AVSessionNapiUtils::SetValueString(env, "subtitle", aVMetaData.GetSubTitle(), result);
    AVSessionNapiUtils::SetValueString(env, "description", aVMetaData.GetDescription(), result);
    AVSessionNapiUtils::SetValueString(env, "lyric", aVMetaData.GetLyric(), result);
    AVSessionNapiUtils::SetValueString(env, "previousAssetId", aVMetaData.GetPreviosAssetId(), result);
    AVSessionNapiUtils::SetValueString(env, "nextAssetId", aVMetaData.GetNextAssetId(), result);
}

void AVSessionNapiUtils::WrapNapiToAVPlaybackState(napi_env env, napi_value object, AVPlaybackState& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_object) {
        napi_value res = nullptr;
        if (napi_get_named_property(env, object, "state", &res) == napi_ok) {
            int32_t state = 0;
            napi_get_value_int32(env, res, &state);
            result.SetState(state);
        }
        if (napi_get_named_property(env, object, "speed", &res) == napi_ok) {
            double speed = 0;
            napi_get_value_double(env, res, &speed);
            result.SetSpeed((float)speed);
        }
        if (napi_get_named_property(env, object, "position", &res) == napi_ok) {
            napi_typeof(env, res, &valueType);
            if (valueType == napi_object) {
                napi_value positionRes = nullptr;
                if (napi_get_named_property(env, res, "elapsedTime", &positionRes) == napi_ok) {
                    uint64_t elapsedTime = 0;
                    bool lossless = false;
                    napi_get_value_bigint_uint64(env, positionRes, &elapsedTime, &lossless);
                    result.SetElapsedTime(lossless? elapsedTime:0);
                }
                if (napi_get_named_property(env, res, "updateTime", &positionRes) == napi_ok) {
                    uint64_t updateTime = 0;
                    bool lossless = false;
                    napi_get_value_bigint_uint64(env, positionRes, &updateTime, &lossless);
                    result.SetElapsedTime(lossless? updateTime:0);
                }
            }
        }

        if (napi_get_named_property(env, object, "bufferedTime", &res) == napi_ok) {
            int64_t bufferedTime = 0;
            napi_get_value_int64(env, res, &bufferedTime);
            result.SetBufferedTime(bufferedTime);
        }
        if (napi_get_named_property(env, object, "loopMode", &res) == napi_ok) {
            int32_t loopMode = 0;
            napi_get_value_int32(env, res, &loopMode);
            result.SetLoopMode(loopMode);
        }
        if (napi_get_named_property(env, object, "isFavorite", &res) == napi_ok) {
            bool isFavorite = 0;
            napi_get_value_bool(env, res, &isFavorite);
            result.SetFavorite(isFavorite);
        }
    }
}

void AVSessionNapiUtils::WrapAVPlaybackStateToNapi(napi_env env,
                                                   const AVPlaybackState& aVPlaybackState,
                                                   napi_value& result)
{
    napi_create_object(env, &result);
    AVSessionNapiUtils::SetValueInt32(env, "state", aVPlaybackState.GetState(), result);
    AVSessionNapiUtils::SetValueDouble(env, "speed", aVPlaybackState.GetSpeed(), result);
    AVSessionNapiUtils::SetValueInt64(env, "bufferedTime", aVPlaybackState.GetBufferedTime(), result);
    AVSessionNapiUtils::SetValueInt32(env, "loopMode", aVPlaybackState.GetLoopMode(), result);
    AVSessionNapiUtils::SetValueBool(env, "isFavorite", aVPlaybackState.GetFavorite(), result);
    napi_status status;
    napi_value value = nullptr;
    status = AVSessionNapiUtils::SetValueInt64(env, "elapsedTime", aVPlaybackState.GetElapsedTime(), value);
    status = AVSessionNapiUtils::SetValueInt64(env, "updateTime", aVPlaybackState.GetUpdateTime(), value);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, "position", value);
    }
}

void AVSessionNapiUtils::WrapAVSessionDescriptorToNapi(napi_env env,
                                                       const AVSessionDescriptor& descriptor,
                                                       napi_value& result)
{
    napi_create_object(env, &result);
    AVSessionNapiUtils::SetValueInt32(env, "sessionId", descriptor.sessionId_, result);
    AVSessionNapiUtils::SetValueString(env, "type", GetSessionType(descriptor.sessionType_), result);
    AVSessionNapiUtils::SetValueString(env, "sessionTag", descriptor.sessionTag_, result);
    AVSessionNapiUtils::SetValueString(env, "bundleName", descriptor.elementName_.GetBundleName(), result);
    AVSessionNapiUtils::SetValueString(env, "abilityName", descriptor.elementName_.GetAbilityName(), result);
    AVSessionNapiUtils::SetValueBool(env, "isActive", descriptor.isActive_, result);
    AVSessionNapiUtils::SetValueBool(env, "isTopSession", descriptor.isTopSession_, result);

    napi_status status;
    napi_value value = nullptr;
    status = SetValueBool(env, "isRemote", descriptor.isRemote_, value);

    std::vector<std::string> deviceIds_ = descriptor.deviceIds_;
    napi_value deviceIdsValue = nullptr;
    napi_value deviceIdsValueParam = nullptr;
    size_t deviceIdsSize = deviceIds_.size();
    napi_create_array_with_length(env, deviceIdsSize, &deviceIdsValue);
    for (size_t i = 0; i < deviceIdsSize; i ++) {
        (void)napi_create_object(env, &deviceIdsValueParam);
        napi_create_string_utf8(env, deviceIds_[i].c_str(), NAPI_AUTO_LENGTH, &deviceIdsValueParam);
        status = napi_set_element(env, deviceIdsValue, i, deviceIdsValueParam);
        if (status != napi_ok) {
            return;
        }
    }

    status = napi_set_named_property(env, value, "deviceId", deviceIdsValue);

    std::vector<std::string> deviceNames_ =  descriptor.deviceNames_;
    napi_value deviceNamesValue = nullptr;
    napi_value deviceNamesValueParam = nullptr;
    size_t deviceNamesSize = deviceNames_.size();
    napi_create_array_with_length(env, deviceNamesSize, &deviceNamesValue);
    for (size_t i = 0; i < deviceNamesSize; i ++) {
        (void)napi_create_object(env, &deviceNamesValueParam);
        napi_create_string_utf8(env, deviceNames_[i].c_str(), NAPI_AUTO_LENGTH, &deviceNamesValueParam);
        status = napi_set_element(env, deviceNamesValue, i, deviceNamesValueParam);
        if (status != napi_ok) {
            return;
        }
    }

    status = napi_set_named_property(env, value, "deviceName", deviceNamesValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, "outputDevice", value);
    }
}
}