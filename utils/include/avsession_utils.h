/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <regex>

#include "common_event_manager.h"

#include "avsession_log.h"
#include "directory_ex.h"

namespace OHOS::AVSession {
class AVSessionUtils {
public:
    static constexpr const int32_t MAX_FILE_SIZE = 4 * 1024 * 1024;

    static void WriteImageToFile(const std::shared_ptr<AVSessionPixelMap>& innerPixelMap,
        const std::string& fileDir, const std::string& fileName)
    {
        if (innerPixelMap == nullptr) {
            SLOGE("innerPixelMap is nullptr");
            return;
        }

        char realPath[PATH_MAX] = { 0x00 };
        if (realpath(fileDir.c_str(), realPath) == nullptr
            && !OHOS::ForceCreateDirectory(fileDir)) {
            SLOGE("WriteImageToFile check and create path failed %{public}s", fileDir.c_str());
            return;
        }
        std::string filePath = fileDir + fileName;

        std::vector<uint8_t> tempBuffer = innerPixelMap->GetInnerImgBuffer();
        size_t imgBufferSize = tempBuffer.size();
        SLOGI("write img to file with imgBufferSize=%{public}zu", imgBufferSize);
        if (imgBufferSize > static_cast<size_t>(MAX_FILE_SIZE) || imgBufferSize == 0) {
            SLOGE("error, dataSize larger than %{public}d or invalid", MAX_FILE_SIZE);
            return;
        }

        std::ofstream ofile(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        if (!ofile.is_open()) {
            SLOGE("open file error, filePath=%{public}s", filePath.c_str());
            return;
        }

        ofile.write((char*)&imgBufferSize, sizeof(size_t));
        SLOGI("write imgBuffer after write size %{public}zu", imgBufferSize);
        ofile.write((char*)(&(tempBuffer[0])), imgBufferSize);
        ofile.close();
    }

    static void ReadImageFromFile(std::shared_ptr<AVSessionPixelMap>& innerPixelMap,
        const std::string& fileDir, const std::string& fileName)
    {
        if (innerPixelMap == nullptr) {
            SLOGE("PixelNull:%{public}s", fileDir.c_str());
            return;
        }

        char realPath[PATH_MAX] = { 0x00 };
        if (realpath(fileDir.c_str(), realPath) == nullptr) {
            SLOGE("check path fail:%{public}s", fileDir.c_str());
            return;
        }
        std::string filePath = fileDir + fileName;

        std::ifstream ifile(filePath.c_str(), std::ios::binary | std::ios::in);
        if (!ifile.is_open()) {
            SLOGE("open file err:Path=%{public}s", filePath.c_str());
            return;
        }

        size_t imgBufferSize;
        ifile.read((char*)&imgBufferSize, sizeof(size_t));
        SLOGD("imgBufferSize=%{public}zu", imgBufferSize);
        if (imgBufferSize > static_cast<size_t>(MAX_FILE_SIZE) || imgBufferSize == 0) {
            SLOGE("error, dataSize larger than %{public}d or invalid", MAX_FILE_SIZE);
            ifile.close();
            return;
        }
        std::vector<std::uint8_t> imgBuffer(imgBufferSize);
        ifile.read((char*)&imgBuffer[0], imgBufferSize);
        SLOGD("imgBuffer prepare set");
        innerPixelMap->SetInnerImgBuffer(imgBuffer);
        SLOGD("imgBuffer SetInnerImgBuffer done");
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

    static std::string GetCachePathName()
    {
        return std::string(DATA_PATH_NAME) + PUBLIC_PATH_NAME + CACHE_PATH_NAME;
    }

    static std::string GetCachePathName(int32_t userId)
    {
        return std::string(DATA_PATH_NAME) + std::to_string(userId) + CACHE_PATH_NAME;
    }

    static std::string GetCachePathNameForCast(int32_t userId)
    {
        return std::string(DATA_PATH_NAME) + std::to_string(userId) + CACHE_PATH_NAME + CAST_PREFIX;
    }

    static std::string GetFixedPathName()
    {
        return std::string(DATA_PATH_NAME) + PUBLIC_PATH_NAME + FIXED_PATH_NAME;
    }

    static std::string GetFixedPathName(int32_t userId)
    {
        return std::string(DATA_PATH_NAME) + std::to_string(userId) + FIXED_PATH_NAME;
    }

    static const char* GetFileSuffix()
    {
        return FILE_SUFFIX;
    }
    
    static std::string GetAnonySessionId(const std::string& sessionId)
    {
        constexpr size_t PRE_LEN = 3;
        constexpr size_t MAX_LEN = 100;
        std::string res;
        std::string tmpStr("******");
        size_t len = sessionId.length();

        std::regex nameRegex("[\\w]*");
        if (len < PRE_LEN || len > MAX_LEN) {
            SLOGE("GetAnonySessionId err length %{public}d", static_cast<int>(len));
            return "ERROR_LENGTH";
        }
        if (!std::regex_match(sessionId, nameRegex)) {
            SLOGE("GetAnonySessionId err content");
            return "ERROR_CONTENT";
        }
        res.append(sessionId, 0, PRE_LEN).append(tmpStr).append(sessionId, len - PRE_LEN, PRE_LEN);
        return res;
    }

    static int32_t PublishCommonEvent(const std::string& action)
    {
        OHOS::AAFwk::Want want;
        want.SetAction(action);
        EventFwk::CommonEventData data;
        data.SetWant(want);
        EventFwk::CommonEventPublishInfo publishInfo;
        int32_t ret = EventFwk::CommonEventManager::NewPublishCommonEvent(data, publishInfo);
        SLOGI("PublishCommonEvent: %{public}s return %{public}d", action.c_str(), ret);
        return ret;
    }

    static std::string GetAnonyTitle(const std::string& title, double ratio = 0.3)
    {
        if (title.empty()) return "";
        // UTF-8字符边界常量
        const unsigned char UTF8_CONTINUATION_BYTE_MASK = 0xC0;    // 11000000
        const unsigned char UTF8_CONTINUATION_BYTE_VALUE = 0x80;   // 10000000
        const unsigned char UTF8_3BYTE_START_MIN = 0xE0;           // 11100000
        const unsigned char UTF8_3BYTE_START_MAX = 0xEF;           // 11101111
        // 统计字符位置（处理UTF-8多字节字符）
        std::vector<int> char_positions;
        for (size_t i = 0; i < title.size(); ++i) {
            if ((static_cast<unsigned char>(title[i]) & UTF8_CONTINUATION_BYTE_MASK) != UTF8_CONTINUATION_BYTE_VALUE) {
                char_positions.push_back(i);
            }
        }
        const int char_count = char_positions.size();
        // 特殊处理短字符串
        const int VERY_SHORT_TEXT_LENGTH = 3;
        if (char_count <= VERY_SHORT_TEXT_LENGTH) {
            // 3字节UTF-8字符的特殊处理
            if (char_count == 3) {
                const unsigned char first_byte = static_cast<unsigned char>(title[0]);
                if (first_byte >= UTF8_3BYTE_START_MIN && first_byte <= UTF8_3BYTE_START_MAX) {
                    return "*" + title + "*";
                }
            }
            // 2字符文本的处理
            if (char_count == 2) {
                return std::string(1, title[0]) + "***";
            }
            // 单字符直接返回
            return "*" + title + "*";
        }
        // 掩码参数配置
        const int SHORT_TEXT_THRESHOLD = 7;                              // 短文本阈值
        const int LONG_TEXT_FRONT_KEEP = 2;                              // 长文本前保留字符数
        const int LONG_TEXT_BACK_KEEP = 2;                               // 长文本后保留字符数
        const int MIN_KEEP_COUNT = 1;                                    // 最少保留字符数
        int keep_front = 0;
        int keep_back = 0;

        if (char_count <= SHORT_TEXT_THRESHOLD) {
            // 短文本：按比例计算掩码长度
            const int mask_len = static_cast<int>(std::ceil(char_count * ratio));
            const int DIVISOR_FOR_HALF_CALCULATION = 2;  // 用于计算一半的除数
            keep_front = (char_count - mask_len) / DIVISOR_FOR_HALF_CALCULATION;
            keep_back = char_count - mask_len - keep_front;
            // 确保前后至少保留1个字符
            keep_front = std::max(keep_front, MIN_KEEP_COUNT);
            keep_back = std::max(keep_back, MIN_KEEP_COUNT);
        } else {
            // 长文本：固定保留前后2个字符
            keep_front = LONG_TEXT_FRONT_KEEP;
            keep_back = LONG_TEXT_BACK_KEEP;
        }
        // 边界安全检查：如果保留字符数超过总字符数
        if (keep_front + keep_back >= char_count) return std::string(1, title[0]) + "***";
        // 构建匿名化字符串
        const int start_idx = char_positions[keep_front];                    // 掩码开始位置
        const int end_idx = char_positions[char_count - keep_back];          // 掩码结束位置

        return title.substr(0, start_idx) + "***" + title.substr(end_idx);
    }

private:
    static constexpr const char* DATA_PATH_NAME = "/data/service/el2/";
    static constexpr const char* CACHE_PATH_NAME = "/av_session/cache/";
    static constexpr const char* FIXED_PATH_NAME = "/av_session/";
    static constexpr const char* PUBLIC_PATH_NAME = "public";
    static constexpr const char* FILE_SUFFIX = ".image.dat";
    static constexpr const char* CAST_PREFIX = "cast_";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_UTILS_H