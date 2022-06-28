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

#include "avsession_dumper.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
const std::string ARGS_HELP = "-h";
const std::string ARGS_SHOW_METADATA = "-show_metadata";
const std::string ILLEGAL_INFORMATION = "AVSession service, enter '-h' for usage.\n";

void AVSessionDumper::ShowHelp(std::string& result) const
{
    result.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-show_metadata          :")
        .append("dump all avsession metadata in the system\n");
}

void AVSessionDumper::ShowMetaData(std::string& result,
                                   std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers) const
{
    int32_t controllerIndex = 0;
    int32_t itemIndex = 0;
    for (auto &it : controllers) {
        result.append("ControllerIndex: " + std::to_string(++controllerIndex) + "\n");
        std::list<sptr<AVControllerItem>>::iterator item;
        for (item = it.second.begin(); item != it.second.end(); item++) {
            result.append("ItemIndex: " + std::to_string(++itemIndex)+ "\n");
            sptr<AVControllerItem> controllerItem = *item;
            AVMetaData metaData;
            controllerItem->GetAVMetaData(metaData);

            result.append("AVSession MetaData:\n");
            result.append("        assetid: " + metaData.GetAssetId() + "\n");
            result.append("        title: " + metaData.GetTitle() + "\n");
            result.append("        artist: " + metaData.GetArtist() + "\n");
            result.append("        author: " + metaData.GetAuthor() + "\n");
            result.append("        album: " + metaData.GetAlbum() + "\n");
            result.append("        writer: " + metaData.GetWriter() + "\n");
            result.append("        composer: " + metaData.GetComposer() + "\n");
            result.append("        duration: " + std::to_string(metaData.GetDuration()) + "\n");
            result.append("        mediaimageurl: " + metaData.GetMediaImageUri() + "\n");
            result.append("        publishdate: " + std::to_string(metaData.GetPublishDate()) + "\n");
            result.append("        subtitle: " + metaData.GetSubTitle() + "\n");
            result.append("        description: " + metaData.GetDescription() + "\n");
            result.append("        lyric: " + metaData.GetLyric() + "\n");
            result.append("        previosassetid: " + metaData.GetPreviousAssetId() + "\n");
        }
    }
}

void AVSessionDumper::ProcessParameter(const std::string& arg, std::string& result,
                                       std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers) const
{
    if (arg == ARGS_HELP) {
        ShowHelp(result);
    } else if (arg == ARGS_SHOW_METADATA) {
        ShowMetaData(result, controllers);
    } else {
        ShowHelp(result);
    }
}

void AVSessionDumper::ShowIllegalInfo(std::string& result) const
{
    result.append(ILLEGAL_INFORMATION);
}

void AVSessionDumper::Dump(const std::vector<std::string>& args, std::string& result,
    std::map<pid_t, std::list<sptr<AVControllerItem>>> controllers) const
{
    result.clear();
    auto argsSize = args.size();
    if (argsSize == 1) {
        ProcessParameter(args[0], result, controllers);
    } else {
        ShowIllegalInfo(result);
    }
}
} // namespace OHOS::AVSession