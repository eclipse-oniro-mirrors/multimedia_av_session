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

#ifndef OHOS_AVSESSION_NAPI_UTILS_H
#define OHOS_AVSESSION_NAPI_UTILS_H

#include <map>
#include "key_event.h"
#include "av_session.h"
#include "avcontrol_command.h"
#include "avmeta_data.h"
#include "avsession_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS::AVSession {
class AVSessionNapiUtils {
public:
    AVSessionNapiUtils() {}
    ~AVSessionNapiUtils() {}

    static napi_status CreateJSObject(napi_env env,
                                      napi_value exports,
                                      std::string className,
                                      napi_callback constructor,
                                      napi_property_descriptor* properties,
                                      size_t propertyCount,
                                      napi_ref* result);
    static napi_value NapiUndefined(napi_env env);
    static napi_value CreateNapiString(napi_env env, std::string str);
    static napi_status SetValueInt32(const napi_env& env, const std::string& fieldStr,
                                     const int32_t intValue, napi_value& result);
    static napi_status SetValueInt64(const napi_env& env, const std::string& fieldStr,
                                     const int64_t intValue, napi_value& result);
    static napi_status SetValueString(const napi_env& env, const std::string& fieldStr,
                                      const std::string& stringValue, napi_value& result);
    static napi_status SetValueBool(const napi_env& env, const std::string& fieldStr,
                                    const bool& boolValue, napi_value& result);
    static napi_status SetValueDouble(const napi_env& env, const std::string& fieldStr,
                                      const double doubleValue, napi_value& result);
    static int GetValueInt32(const napi_env& env, const std::string& fieldStr, const napi_value& value);
    static bool GetValueBool(const napi_env& env, const std::string& fieldStr, const napi_value& value);
    static std::string GetValueString(const napi_env& env, const std::string& fieldStr, const napi_value& value);
    static double GetValueDouble(const napi_env& env, const std::string& fieldStr, const napi_value& value);
    static napi_value WrapVoidToJS(napi_env env);
    static std::string GetSessionType(const int32_t type);
    static std::string GetStringArgument(napi_env env, napi_value value);
    static void WrapNapiToAVMetadata(napi_env env, napi_value object, AVMetaData& result);
    static void WrapAVMetadataToNapi(napi_env env, const AVMetaData& aVMetaData, napi_value& result);
    static void WrapNapiToAVPlaybackState(napi_env env, napi_value object, AVPlaybackState& result);
    static void WrapAVPlaybackStateToNapi(napi_env env, const AVPlaybackState& aVPlaybackState, napi_value& result);
    static void WrapAVSessionDescriptorToNapi(napi_env env, const AVSessionDescriptor& descriptor, napi_value& result);
    static void WrapNapiToKeyEvent(napi_env env, napi_value object, std::shared_ptr<MMI::KeyEvent>& result);

    static const int ARGS_ONE = 1;
    static const int ARGS_TWO = 2;
    static const int PARAM0 = 0;
    
private:

    static void WrapAssetId(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapTitile(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapArtist(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapAuthor(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapAlbum(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapWriter(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapComposer(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapDuration(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapMediaImage(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapMediaImageUri(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapPublishData(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapSubTitile(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapDescriptiion(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapLyric(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapPreviousAssetId(napi_env env, const AVMetaData& value, napi_value& result);
    static void WrapNextAssetId(napi_env env, const AVMetaData& value, napi_value& result);

    using WrapAVMetaData = void(*)(napi_env env, const AVMetaData& value, napi_value& result);
    static inline WrapAVMetaData wrapAVMetaData[AVMetaData::META_KEY_MAX] = {
        [AVMetaData::META_KEY_ASSET_ID] = &AVSessionNapiUtils::WrapAssetId,
        [AVMetaData::META_KEY_TITLE] = &AVSessionNapiUtils::WrapTitile,
        [AVMetaData::META_KEY_ARTIST] = &AVSessionNapiUtils::WrapArtist,
        [AVMetaData::META_KEY_AUTHOR] = &AVSessionNapiUtils::WrapAuthor,
        [AVMetaData::META_KEY_ALBUM] = &AVSessionNapiUtils::WrapAlbum,
        [AVMetaData::META_KEY_WRITER] = &AVSessionNapiUtils::WrapWriter,
        [AVMetaData::META_KEY_COMPOSER] = &AVSessionNapiUtils::WrapComposer,
        [AVMetaData::META_KEY_DURATION] = &AVSessionNapiUtils::WrapDuration,
        [AVMetaData::META_KEY_MEDIA_IMAGE] = &AVSessionNapiUtils::WrapMediaImage,
        [AVMetaData::META_KEY_MEDIA_IMAGE_URI] = &AVSessionNapiUtils::WrapMediaImageUri,
        [AVMetaData::META_KEY_PUBLISH_DATE] = &AVSessionNapiUtils::WrapPublishData,
        [AVMetaData::META_KEY_SUBTITLE] = &AVSessionNapiUtils::WrapSubTitile,
        [AVMetaData::META_KEY_DESCRIPTION] = &AVSessionNapiUtils::WrapDescriptiion,
        [AVMetaData::META_KEY_LYRIC] = &AVSessionNapiUtils::WrapLyric,
        [AVMetaData::META_KEY_PREVIOUS_ASSET_ID] = &AVSessionNapiUtils::WrapPreviousAssetId,
        [AVMetaData::META_KEY_NEXT_ASSET_ID] = &AVSessionNapiUtils::WrapNextAssetId,
    };
};

static std::map<std::string, int32_t> aVControlCommandMap = {
    {"play", AVControlCommand::SESSION_CMD_PLAY},
    {"pause", AVControlCommand::SESSION_CMD_PAUSE},
    {"stop", AVControlCommand::SESSION_CMD_STOP},
    {"playNext", AVControlCommand::SESSION_CMD_PLAY_NEXT},
    {"playPrevious", AVControlCommand::SESSION_CMD_PLAY_PREVIOUS},
    {"fastForward", AVControlCommand::SESSION_CMD_FAST_FORWARD},
    {"rewind", AVControlCommand::SESSION_CMD_REWIND},
    {"seek", AVControlCommand::SESSION_CMD_SEEK},
    {"setSpeed", AVControlCommand::SESSION_CMD_SET_SPEED},
    {"setLoopMode", AVControlCommand::SESSION_CMD_SET_LOOP_MODE},
    {"toggleFavorite", AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE}
};

static std::map<int32_t, std::string> aVControlCommandToStrMap = {
    {AVControlCommand::SESSION_CMD_PLAY, "play"},
    {AVControlCommand::SESSION_CMD_PAUSE, "pause"},
    {AVControlCommand::SESSION_CMD_STOP, "stop"},
    {AVControlCommand::SESSION_CMD_PLAY_NEXT, "playNext"},
    {AVControlCommand::SESSION_CMD_PLAY_PREVIOUS, "playPrevious"},
    {AVControlCommand::SESSION_CMD_FAST_FORWARD, "fastForward"},
    {AVControlCommand::SESSION_CMD_REWIND, "rewind"},
    {AVControlCommand::SESSION_CMD_SEEK, "seek"},
    {AVControlCommand::SESSION_CMD_SET_SPEED, "setSpeed"},
    {AVControlCommand::SESSION_CMD_SET_LOOP_MODE, "setLoopMode"},
    {AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE, "toggleFavorite"}
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_NAPI_UTILS_H