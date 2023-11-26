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

namespace OHOS::AVSession {
class Base64Utils {
public:
    static std::string Base64Encode(const char *data)
    {
        char out[MAX_LENGTH] = {0};
        int dataLen = strlen(data);
        if (dataLen == 0) {
            out[0] = '\0';
            return "";
        }

        int index = 0;
        char c = '\0';
        char lastC = '\0';

        for (int i = 0; i < dataLen; i++) {
            c = data[i];
            switch (i % NUMBER_THREE) {
                case 0:
                    out[index++] = BASE64_EN[(c >> NUMBER_TWO) & 0x3f];
                    break;
                case 1:
                    out[index++] = BASE64_EN[(lastC & 0x3) << NUMBER_FOUR | ((c >> NUMBER_FOUR) & 0xf)];
                    break;
                case NUMBER_TWO:
                    out[index++] = BASE64_EN[(lastC & 0xf) << NUMBER_TWO | ((c >> NUMBER_SIX) & 0x3)];
                    out[index++] = BASE64_EN[c & 0x3f];
                    break;
                default:
                    break;
            }
            lastC = c;
        }

        if (dataLen % NUMBER_THREE == NUMBER_ONE) {
            out[index++] = BASE64_EN[(c & 0x3) << NUMBER_FOUR];
            out[index++] = '=';
            out[index++] = '=';
        }

        if (dataLen % NUMBER_THREE == NUMBER_TWO) {
            out[index++] = BASE64_EN[(c & 0xf) << NUMBER_TWO];
            out[index++] = '=';
        }
        return std::string(out);
}

private:
    static constexpr const int MAX_LENGTH = 1024;
    static constexpr const int NUMBER_ONE = 1;
    static constexpr const int NUMBER_TWO = 2;
    static constexpr const int NUMBER_THREE = 3;
    static constexpr const int NUMBER_FOUR = 4;
    static constexpr const int NUMBER_SIX = 6;
    static constexpr const char BASE64_EN[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
        'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
        '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };
};
} // namespace OHOS::AVSession

#endif // AVSESSION_BASE64_UTILS_H
