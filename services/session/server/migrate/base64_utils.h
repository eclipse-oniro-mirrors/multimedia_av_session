/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef AVSESSION_BASE64_UTILS_H
#define AVSESSION_BASE64_UTILS_H

#include <cstring>
#include <string>
#include <iostream>
#include <vector>

namespace OHOS::AVSession {
class Base64Utils {
public:
    static std::string base64_encode(const std::vector<uint8_t> &data)
    {
        std::string encoded;
        int i = 0;
        uint8_t byte3[3] = {0};
        uint8_t byte4[4] = {0};
        for (uint8_t byte : data) {
            byte3[i++] = byte;
            if (i == 3) {
                byte4[0] = (byte3[0] & 0xfc) >> 2;
                byte4[1] = ((byte3[0] & 0x03) << 4) | ((byte3[1] & 0xf0) >> 4);
                byte4[2] = ((byte3[1] & 0x0f) << 2) | ((byte3[2] & 0xc0) >> 6);
                byte4[3] = byte3[2] & 0x3f;
                for (i = 0; i < 4; i++) {
                    encoded += base64_chars[byte4[i]];
                }
                i = 0;
            }
        }
        if (i != 0) {
            for (int k = i; k < 3; k++) {
                byte3[k] = 0;
            }
            byte4[0] = (byte3[0] & 0xfc) >> 2;
            byte4[1] = ((byte3[0] & 0x03) << 4) | ((byte3[1] & 0xf0) >> 4);
            byte4[2] = ((byte3[1] & 0x0f) << 2) | ((byte3[2] & 0xc0) >> 6);
            for (int k = 0; k < i + 1; k++) {
                encoded += base64_chars[byte4[k]];
            }
            while (i++ < 3) {
                encoded += '=';
            }
        }
        return encoded;
    }
private:
    static const std::string base64_chars;
};
const std::string Base64::base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "abcdefghijklmnopqrstuvwxyz"
                                         "0123456789+/";
} // namespace OHOS::AVSession

#endif // AVSESSION_BASE64_UTILS_H
