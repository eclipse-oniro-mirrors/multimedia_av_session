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
    static constexpr int kNumberZero = 0;
    static constexpr int kNumberOne = 1;
    static constexpr int kNumberTwo = 2;
    static constexpr int kNumberThree = 3;
    static constexpr int kNumberFour = 4;
    static constexpr int kNumberSix = 6;
public:
    static std::string Base64Encode(const std::vector<uint8_t>& data)
    {
        std::string encoded;
        int i = 0;
        uint8_t byte3[kNumberThree] = {0};
        uint8_t byte4[kNumberFour] = {0};
        for (uint8_t byte : data) {
            byte3[i++] = byte;
            if (i == kNumberThree) {
                byte4[kNumberZero] = (byte3[kNumberZero] & 0xfc) >> kNumberTwo;
                byte4[kNumberOne] = ((byte3[kNumberZero] & 0x03) << kNumberFour) | 
                                    ((byte3[kNumberOne] & 0xf0) >> kNumberFour);
                byte4[kNumberTwo] = ((byte3[kNumberOne] & 0x0f) << kNumberTwo) | 
                                    ((byte3[kNumberTwo] & 0xc0) >> kNumberSix);
                byte4[kNumberThree] = byte3[kNumberTwo] & 0x3f;
                for (i = 0; i < kNumberFour; i++) {
                    encoded += kBase64Chars[byte4[i]];
                }
                i = kNumberZero;
            }
        }
        if (i != kNumberZero) {
            for (int k = i; k < kNumberThree; k++) {
                byte3[k] = kNumberZero;
            }
            byte4[kNumberZero] = (byte3[kNumberZero] & 0xfc) >> kNumberTwo;
            byte4[kNumberOne] = ((byte3[kNumberZero] & 0x03) << kNumberFour) | 
                                ((byte3[kNumberOne] & 0xf0) >> kNumberFour);
            byte4[kNumberTwo] = ((byte3[kNumberOne] & 0x0f) << kNumberTwo) | 
                                ((byte3[kNumberTwo] & 0xc0) >> kNumberSix);
            for (int k = 0; k < i + kNumberOne; k++) {
                encoded += kBase64Chars[byte4[k]];
            }
            while (i++ < kNumberThree) {
                encoded += '=';
            }
        }
        return encoded;
    }
private:
    static const std::string kBase64Chars;
};
const std::string Base64Utils::kBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                              "abcdefghijklmnopqrstuvwxyz"
                                              "0123456789+/";
} // namespace OHOS::AVSession

#endif // AVSESSION_BASE64_UTILS_H
