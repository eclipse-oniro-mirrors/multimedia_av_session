/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_OHAVSESSION_UTILS_H
#define OHOS_OHAVSESSION_UTILS_H

#include "pixel_map.h"
#include "avmeta_data.h"
#include "event_handler.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "native_avqueueitem.h"

namespace OHOS::AVSession {
class AVSessionNdkUtils {
public:
    static int32_t DownloadAndSetCoverImage(const std::string &uri, AVMetaData &meta);
    static int32_t DownloadAndSetCastIcon(const std::string &uri, std::shared_ptr<AVMediaDescription> &description);

    static AVSession_ErrCode ConvertOHQueueItemToInner(OH_AVSession_AVQueueItem *srcItem, AVQueueItem &dstItem);

private:
    static bool DownloadImage(const std::string &uri, std::shared_ptr<Media::PixelMap> &pixelMap);
    static bool CurlSetRequestOptions(const std::string &uri, std::vector<std::uint8_t> &imgBuffer);
    static size_t WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb, std::vector<std::uint8_t> *imgBuffer);

    static constexpr size_t TIME_OUT_SECOND = 5;
    static constexpr int32_t HTTP_ERROR_CODE = 400;
};

class AVSessionDownloadHandler : public AppExecFwk::EventHandler {
public:
    static AVSessionDownloadHandler& GetInstance();

    AVSessionDownloadHandler();
    ~AVSessionDownloadHandler() override;

    bool AVSessionDownloadPostTask(const Callback &callback, const std::string &name = std::string(),
        int64_t delayTime = 0);

    void AVSessionDownloadRemoveTask(const std::string &name);

    void AVSessionDownloadRemoveHandler();

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    std::mutex handlerLock_;
};

class AVSessionDataTracker {
public:
    bool IsDownloadNeeded() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return !(downloadedAssetId_ == currentAssetId_ && downloadedUri_ == currentUri_);
    }

    bool IsOutOfDate(const std::string &assetId, const std::string &uri) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return (assetId != currentAssetId_) ||
            (!currentUri_.empty() && uri != currentUri_) ||
            (downloadedAssetId_ == currentAssetId_ && downloadedUri_ == currentUri_);
    }

    void OnDataUpdated(const std::string &assetId, const std::string &uri, bool isUpdateDownloadedUri)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        downloadedAssetId_ = (assetId != currentAssetId_) ? "" : downloadedAssetId_;
        downloadedUri_ = isUpdateDownloadedUri ? "" : downloadedUri_;
        currentAssetId_ = assetId;
        currentUri_ = uri;
    }

    void OnDownloadCompleted(const std::string &assetId, const std::string &uri)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        downloadedAssetId_ = assetId;
        downloadedUri_ = uri;
    }

private:
    mutable std::mutex mutex_;
    std::string currentAssetId_;
    std::string currentUri_;
    std::string downloadedAssetId_;
    std::string downloadedUri_;
};
}

#endif // OHOS_OHAVSESSION_UTILS_H
