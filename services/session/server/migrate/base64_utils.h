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
    static const int NUMBER_ZERO = 0;
    static const int NUMBER_ONE = 1;
    static const int NUMBER_TWO = 2;
    static const int NUMBER_THREE = 3;
    static const int NUMBER_FOUR = 4;
    static const int NUMBER_SIX = 6;

public:
    static std::string Base64Encode(const std::vector<uint8_t> &data)
    {
        std::string encoded;
        int i = 0;
        uint8_t byte3[NUMBER_THREE] = {0};
        uint8_t byte4[NUMBER_FOUR] = {0};
        for (uint8_t byte : data) {
            byte3[i++] = byte;
            if (i == NUMBER_THREE) {
                byte4[NUMBER_ZERO] = (byte3[NUMBER_ZERO] & 0xfc) >> NUMBER_TWO;
                byte4[NUMBER_ONE] =
                    ((byte3[NUMBER_ZERO] & 0x03) << NUMBER_FOUR) | ((byte3[NUMBER_ONE] & 0xf0) >> NUMBER_FOUR);
                byte4[NUMBER_TWO] =
                    ((byte3[NUMBER_ONE] & 0x0f) << NUMBER_TWO) | ((byte3[NUMBER_TWO] & 0xc0) >> NUMBER_SIX);
                byte4[NUMBER_THREE] = byte3[NUMBER_TWO] & 0x3f;
                for (i = 0; i < NUMBER_FOUR; i++) {
                    encoded += base64_chars[byte4[i]];
                }
                i = 0;
            }
        }
        if (i != 0) {
            for (int k = i; k < NUMBER_THREE; k++) {
                byte3[k] = 0;
            }
            byte4[NUMBER_ZERO] = (byte3[NUMBER_ZERO] & 0xfc) >> NUMBER_TWO;
            byte4[NUMBER_ONE] =
                ((byte3[NUMBER_ZERO] & 0x03) << NUMBER_FOUR) | ((byte3[NUMBER_ONE] & 0xf0) >> NUMBER_FOUR);
            byte4[NUMBER_TWO] = ((byte3[NUMBER_TWO] & 0x0f) << NUMBER_TWO) | ((byte3[NUMBER_TWO] & 0xc0) >> NUMBER_SIX);
            for (int k = 0; k < i + 1; k++) {
                encoded += base64_chars[byte4[k]];
            }
            while (i++ < NUMBER_THREE) {
                encoded += '=';
            }
        }
        return encoded;
    }

private:
    static const std::string base64_chars;
};
const std::string Base64Utils::base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                              "abcdefghijklmnopqrstuvwxyz"
                                              "0123456789+/";
} // namespace OHOS::AVSession

#endif // AVSESSION_BASE64_UTILS_H
