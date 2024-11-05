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

#ifndef OHOS_AVSESSION_LOG_H
#define OHOS_AVSESSION_LOG_H

#include <cinttypes>

#include "hilog/log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002B91

#undef LOG_TAG
#define LOG_TAG "AVSession"

#define AV_SESSION_FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define DECORATOR_HILOG(func, fmt, args...)                                                      \
    do {                                                                                         \
        (void)func(LOG_CORE, "[%{public}s()-%{public}s:%{public}d] " fmt, __FUNCTION__, AV_SESSION_FILENAME, __LINE__, \
                   ##args); \
    } while (0)

#define SLOGD(fmt, ...) DECORATOR_HILOG(HILOG_DEBUG, fmt, ##__VA_ARGS__)
#define SLOGI(fmt, ...) DECORATOR_HILOG(HILOG_INFO, fmt, ##__VA_ARGS__)
#define SLOGW(fmt, ...) DECORATOR_HILOG(HILOG_WARN, fmt, ##__VA_ARGS__)
#define SLOGE(fmt, ...) DECORATOR_HILOG(HILOG_ERROR, fmt, ##__VA_ARGS__)
#define SLOGF(fmt, ...) DECORATOR_HILOG(HILOG_FATAL, fmt, ##__VA_ARGS__)

#define POINTER_MASK 0x00FFFFFF
#define FAKE_POINTER(addr) (POINTER_MASK & reinterpret_cast<uintptr_t>(addr))

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)  \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE(fmt, ##__VA_ARGS__);                 \
            return ret;                                \
        }                                              \
    } while (0)

#define CHECK_AND_RETURN_LOG(cond, fmt, ...)           \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE(fmt, ##__VA_ARGS__);                 \
            return;                                    \
        }                                              \
    } while (0)

#define CHECK_AND_BREAK_LOG(cond, fmt, ...)            \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE(fmt, ##__VA_ARGS__);                 \
            break;                                     \
        }                                              \
    } while (0)

#define CHECK_AND_CONTINUE_LOG(cond, fmt, ...)         \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE(fmt, ##__VA_ARGS__);                 \
            continue;                                  \
        }                                              \
    } while (0)

#define CHECK_AND_PRINT_LOG(cond, fmt, ...)            \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE(fmt, ##__VA_ARGS__);                 \
        }                                              \
    } while (0)

#define CHECK_AND_RETURN_RET(cond, ret)                \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE("%{public}s, check failed! ret = %{public}s", #cond, #ret); \
            return ret;                                \
        }                                              \
    } while (0)

#define CHECK_AND_RETURN(cond)                         \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE("%{public}s, check failed!", #cond); \
            return;                                    \
        }                                              \
    } while (0)

#define CHECK_AND_BREAK(cond)                          \
    do {                                               \
        if (!(cond)) {                                 \
            SLOGE("%{public}s, check failed!", #cond); \
            break;                                     \
        }                                              \
    } while (0)

#define CHECK_AND_CONTINUE(cond)                       \
        if (!(cond)) {                                 \
            SLOGE("%{public}s, check failed!", #cond); \
            continue;                                  \
        }
#endif // OHOS_AVSESSION_LOG_H
