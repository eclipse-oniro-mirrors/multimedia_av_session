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
    napi_status status = napi_set_named_property(env, result, fieldStr.c_str(),
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
        char buffer[(bufLength + 1) * sizeof(char)];
        status = napi_get_value_string_utf8(env, value, buffer, bufLength + 1, &bufLength);
        if (status == napi_ok) {
            SLOGI("argument = %{public}s", buffer);
            strValue = buffer;
        }
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

#define WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, key, res, func)     \
    do {                                                                          \
        if (napi_get_named_property((env), (object), (key), (&res)) == napi_ok) { \
            (result).func(AVSessionNapiUtils::GetStringArgument((env), (res)));   \
        }                                                                         \
    } while (0)

#define WRAP_NAPI_TO_VALUE(env, object, result, key, res, data, napiFunc, resultFunc) \
    do {                                                                              \
        if (napi_get_named_property((env), (object), (key), (&res)) == napi_ok) {     \
            napiFunc((env), (res), &(data));                                          \
            (result).resultFunc(data);                                                \
        }                                                                             \
    } while (0)

void AVSessionNapiUtils::WrapNapiToAVMetadata(napi_env env, napi_value object, AVMetaData& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        SLOGE("WrapNapiToAVMetadata valueType is incorrect");
        return;
    }
    std::string assetId = AVSessionNapiUtils::GetValueString(env, "assetId", object);
    if (assetId.empty()) {
        SLOGE("AVMetaData assetId is null ");
        return;
    }
    result.SetAssetId(assetId);
    napi_value res = nullptr;
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "title", res, SetTitle);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "artist", res, SetArtist);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "author", res, SetAuthor);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "album", res, SetAlbum);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "writer", res, SetWriter);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "composer", res, SetComposer);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "subtitle", res, SetSubTitle);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "description", res, SetDescription);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "lyric", res, SetLyric);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "previousAssetId", res, SetPreviosAssetId);
    WRAP_NAPI_TO_AVMETADATA_PROPERTY(env, object, result, "nextAssetId", res, SetNextAssetId);
    int64_t durationTime = 0;
    WRAP_NAPI_TO_VALUE(env, object, result, "duration", res, durationTime, napi_get_value_int64, SetDuration);
    double publishDate = 0.0f;
    WRAP_NAPI_TO_VALUE(env, object, result, "publishDate", res, publishDate, napi_get_date_value, SetPublishDate);
    if (napi_get_named_property(env, object, "mediaImage", &res) != napi_ok) {
        SLOGE("AVMetaData get mediaImage fail ");
        return;
    }
    valueType = napi_undefined;
    napi_typeof(env, res, &valueType);
    if (valueType == napi_string) {
        std::string mediaImageUri = AVSessionNapiUtils::GetStringArgument(env, res);
        result.SetMediaImageUri(mediaImageUri);
    } else {
        std::shared_ptr<Media::PixelMap> mediaImage = nullptr;
        napi_status status = napi_unwrap(env, res, (void**)&mediaImage);
        if (status != napi_ok || mediaImage == nullptr) {
            SLOGE("napi_unwrap mediaImage error");
            return;
        }
        result.SetMediaImage(mediaImage);
    }
}

void AVSessionNapiUtils::WrapAVMetadataToNapi(napi_env env, const AVMetaData& aVMetaData, napi_value& result)
{
    napi_create_object(env, &result);
    for (int i = 0; i < AVMetaData::META_KEY_MAX; i++) {
        if (aVMetaData.GetMetaMask().test(i)) {
            wrapAVMetaData[i](env, aVMetaData, result);
        }
    }
}

void AVSessionNapiUtils::WrapNapiToAVPlaybackState(napi_env env, napi_value object, AVPlaybackState& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        SLOGE("WrapNapiToAVPlaybackState valueType error");
        return;
    }
    napi_value res = nullptr;
    int32_t state = 0;
    WRAP_NAPI_TO_VALUE(env, object, result, "state", res, state, napi_get_value_int32, SetSpeed);
    double speed = 0.0;
    WRAP_NAPI_TO_VALUE(env, object, result, "speed", res, speed, napi_get_value_double, SetSpeed);
    int64_t time = 0;
    WRAP_NAPI_TO_VALUE(env, object, result, "bufferedTime", res, time, napi_get_value_int64, SetBufferedTime);
    int32_t loopMode = 0;
    WRAP_NAPI_TO_VALUE(env, object, result, "loopMode", res, loopMode, napi_get_value_int32, SetLoopMode);
    bool isFavorite = false;
    WRAP_NAPI_TO_VALUE(env, object, result, "isFavorite", res, isFavorite, napi_get_value_bool, SetFavorite);

    napi_value positionObject = nullptr;
    if (napi_get_named_property(env, object, "position", &positionObject) != napi_ok) {
        SLOGE("WrapNapiToAVPlaybackState napi_get_named_property error");
        return;
    }
    napi_typeof(env, positionObject, &valueType);
    if (valueType != napi_object) {
        SLOGE("WrapNapiToAVPlaybackState valueType is not napi_object");
        return;
    }
    napi_value positionRes = nullptr;
    if (napi_get_named_property(env, positionObject, "elapsedTime", &positionRes) == napi_ok) {
        uint64_t elapsedTime = 0;
        bool lossless = false;
        napi_get_value_bigint_uint64(env, positionRes, &elapsedTime, &lossless);
        result.SetElapsedTime(lossless ? elapsedTime : 0);
    }
    if (napi_get_named_property(env, positionObject, "updateTime", &positionRes) == napi_ok) {
        uint64_t updateTime = 0;
        bool lossless = false;
        napi_get_value_bigint_uint64(env, positionRes, &updateTime, &lossless);
        result.SetElapsedTime(lossless ? updateTime:0);
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

void AVSessionNapiUtils::WrapNapiToKeyEvent(napi_env env, napi_value object, std::shared_ptr<MMI::KeyEvent>& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_object) {
        SLOGE("The keyEvent parameter is invalid");
        return;
    }
    SLOGE("The keyEvent parameter is napi_object");
    result = MMI::KeyEvent::Create();
    if (result == nullptr) {
        SLOGE("keyEvent is null");
        return;
    }
    SLOGE("The keyEvent MMI::KeyEvent::Create is success");
    bool isPressed = GetValueBool(env, "isPressed", object);
    if (isPressed) {
        result->SetKeyAction(MMI::KeyEvent::KEY_ACTION_DOWN);
    } else {
        result->SetKeyAction(MMI::KeyEvent::KEY_ACTION_UP);
    }
    int32_t keyCode = GetValueInt32(env, "keyCode", object);
    result->SetKeyCode(keyCode);
    bool isIntercepted = false;
    if (!isIntercepted) {
        result->AddFlag(MMI::InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    int32_t keyDownDuration = GetValueInt32(env, "keyDownDuration", object);
    MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    item.SetDownTime(static_cast<int64_t>(keyDownDuration));
    result->AddKeyItem(item);
}

void AVSessionNapiUtils::WrapAssetId(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "assetId", value.GetAssetId(), result);
}

void AVSessionNapiUtils::WrapTitile(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "title", value.GetTitle(), result);
}

void AVSessionNapiUtils::WrapArtist(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "artist", value.GetArtist(), result);
}

void AVSessionNapiUtils::WrapAuthor(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "author", value.GetAuthor(), result);
}

void AVSessionNapiUtils::WrapAlbum(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "album", value.GetAlbum(), result);
}

void AVSessionNapiUtils::WrapWriter(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "writer", value.GetWriter(), result);
}

void AVSessionNapiUtils::WrapComposer(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "composer", value.GetComposer(), result);
}

void AVSessionNapiUtils::WrapDuration(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueInt64(env, "duration", value.GetDuration(), result);
}

void AVSessionNapiUtils::WrapMediaImage(napi_env env, const AVMetaData& value, napi_value& result)
{
    SLOGE("WrapMediaImage piexMap error");
}

void AVSessionNapiUtils::WrapMediaImageUri(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "mediaImage", value.GetMediaImageUri(), result);
}

void AVSessionNapiUtils::WrapPublishData(napi_env env, const AVMetaData& value, napi_value& result)
{
    napi_value publishDateValue = nullptr;
    napi_status status = napi_create_date(env, value.GetPublishDate(), &publishDateValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, result, "publishDate", publishDateValue);
    }
}

void AVSessionNapiUtils::WrapSubTitile(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "subtitle", value.GetSubTitle(), result);
}

void AVSessionNapiUtils::WrapDescriptiion(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "description", value.GetDescription(), result);
}

void AVSessionNapiUtils::WrapLyric(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "lyric", value.GetLyric(), result);
}

void AVSessionNapiUtils::WrapPreviousAssetId(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "previousAssetId", value.GetPreviosAssetId(), result);
}

void AVSessionNapiUtils::WrapNextAssetId(napi_env env, const AVMetaData& value, napi_value& result)
{
    AVSessionNapiUtils::SetValueString(env, "nextAssetId", value.GetNextAssetId(), result);
}
}