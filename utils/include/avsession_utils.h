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

#ifndef OHOS_AVSESSION_UTILS_H
#define OHOS_AVSESSION_UTILS_H

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "avsession_log.h"
#include "directory_ex.h"

namespace OHOS::AVSession {
class AVSessionUtils {
public:
    static constexpr const int32_t MAX_FILE_SIZE = 200 * 1024;

    static void WriteImageToFile(const std::shared_ptr<AVSessionPixelMap>& innerPixelMap, const std::string& fileName)
    {
        if (innerPixelMap == nullptr) {
            SLOGE("innerPixelMap is nullptr");
            return;
        }

        char realCachePath[PATH_MAX] = { 0x00 };
        char realFixedPath[PATH_MAX] = { 0x00 };
        if (realpath(AVSessionUtils::GetCachePathName(), realCachePath) == nullptr ||
            realpath(AVSessionUtils::GetFixedPathName(), realFixedPath) == nullptr) {
            SLOGE("check path failed %{public}s", AVSessionUtils::GetCachePathName());
            return;
        }

        size_t imgBufferSize = innerPixelMap->GetInnerImgBuffer().size();
        SLOGI("imgBufferSize=%{public}zu", imgBufferSize);
        if (imgBufferSize > MAX_FILE_SIZE || imgBufferSize <= 0) {
            SLOGE("error, dataSize larger than %{public}d or invalid", MAX_FILE_SIZE);
            return;
        }

        std::ofstream ofile(fileName.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        if (!ofile.is_open()) {
            SLOGE("open file error, fileName=%{public}s", fileName.c_str());
            return;
        }

        ofile.write((char*)&imgBufferSize, sizeof(size_t));
        ofile.write((char*)(&(innerPixelMap->GetInnerImgBuffer()[0])), imgBufferSize);
        ofile.close();
    }

    static void ReadImageFromFile(std::shared_ptr<AVSessionPixelMap>& innerPixelMap, const std::string& fileName)
    {
        if (innerPixelMap == nullptr) {
            SLOGE("innerPixelMap is nullptr");
            return;
        }

        char realCachePath[PATH_MAX] = { 0x00 };
        char realFixedPath[PATH_MAX] = { 0x00 };
        if (realpath(AVSessionUtils::GetCachePathName(), realCachePath) == nullptr ||
            realpath(AVSessionUtils::GetFixedPathName(), realFixedPath) == nullptr) {
            SLOGE("check path failed %{public}s", AVSessionUtils::GetCachePathName());
            return;
        }

        std::ifstream ifile(fileName.c_str(), std::ios::binary | std::ios::in);
        if (!ifile.is_open()) {
            SLOGE("open file error, fileName=%{public}s", fileName.c_str());
            return;
        }

        size_t imgBufferSize;
        ifile.read((char*)&imgBufferSize, sizeof(size_t));
        SLOGI("imgBufferSize=%{public}zu", imgBufferSize);
        if (imgBufferSize > MAX_FILE_SIZE || imgBufferSize <= 0) {
            SLOGE("error, dataSize larger than %{public}d or invalid", MAX_FILE_SIZE);
            ifile.close();
            return;
        }
        std::vector<std::uint8_t> imgBuffer(imgBufferSize);
        ifile.read((char*)&imgBuffer[0], imgBufferSize);
        innerPixelMap->SetInnerImgBuffer(imgBuffer);
        ifile.close();
    }

    static void DeleteFile(const std::string& filePath)
    {
        if (OHOS::RemoveFile(filePath)) {
            SLOGI("remove .image.dat file success filePath=%{public}s", filePath.c_str());
        } else {
            SLOGE("remove .image.dat file fail filePath=%{public}s", filePath.c_str());
        }
    }

    static void DeleteCacheFiles(const std::string& path)
    {
        std::vector<std::string> fileList;
        OHOS::GetDirFiles(path, fileList);
        for (const auto& file : fileList) {
            if (file.find(AVSessionUtils::GetFileSuffix()) != std::string::npos) {
                DeleteFile(file);
            }
        }
    }
    static const char* GetCachePathName()
    {
        return CACHE_PATH_NAME;
    }
    
    static const char* GetFixedPathName()
    {
        return FIXED_PATH_NAME;
    }

    static const char* GetFileSuffix()
    {
        return FILE_SUFFIX;
    }

private:
    static constexpr const char* CACHE_PATH_NAME = "/data/service/el1/public/av_session/cache/";
    static constexpr const char* FIXED_PATH_NAME = "/data/service/el1/public/av_session/";
    static constexpr const char* FILE_SUFFIX = ".image.dat";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_UTILS_H