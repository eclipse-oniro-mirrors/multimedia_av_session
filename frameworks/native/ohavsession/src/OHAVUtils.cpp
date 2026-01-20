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

#include "OHAVUtils.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "image_source.h"
#include "curl/curl.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_utils.h"
#include "OHAVMediaDescription.h"

namespace OHOS::AVSession {

AVSession_ErrCode AVSessionNdkUtils::ConvertOHQueueItemToInner(OH_AVSession_AVQueueItem *srcItem, AVQueueItem &dstItem)
{
    CHECK_AND_RETURN_RET_LOG(srcItem != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "avqueueItem is nullptr");
    CHECK_AND_RETURN_RET_LOG(srcItem->description != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "description is nullptr");

    dstItem.SetItemId(static_cast<int32_t>(srcItem->itemId));
    OHOS::AVSession::OHAVMediaDescription *oh_description =
        (OHOS::AVSession::OHAVMediaDescription *)(srcItem->description);
    auto avMediaDescription = std::make_shared<AVMediaDescription>();
    CHECK_AND_RETURN_RET_LOG(avMediaDescription != nullptr, AV_SESSION_ERR_SERVICE_EXCEPTION,
        "create avMediaDescription fail");

    avMediaDescription->SetMediaId(oh_description->GetAssetId());
    avMediaDescription->SetTitle(oh_description->GetTitle());
    avMediaDescription->SetSubtitle(oh_description->GetSubtitle());
    avMediaDescription->SetArtist(oh_description->GetArtist());
    avMediaDescription->SetMediaType(oh_description->GetMediaType());
    avMediaDescription->SetAlbumCoverUri(oh_description->GetAlbumCoverUri());
    avMediaDescription->SetLyricContent(oh_description->GetLyricContent());
    avMediaDescription->SetDuration(oh_description->GetDuration());
    avMediaDescription->SetMediaUri(oh_description->GetMediaUri());
    avMediaDescription->SetStartPosition(oh_description->GetStartPosition());
    avMediaDescription->SetMediaSize(oh_description->GetMediaSize());
    avMediaDescription->SetAlbumTitle(oh_description->GetAlbumTitle());
    avMediaDescription->SetAppName(oh_description->GetAppName());
    dstItem.SetDescription(avMediaDescription);

    return AV_SESSION_ERR_SUCCESS;
}

int32_t AVSessionNdkUtils::DownloadAndSetCoverImage(const std::string &uri, AVMetaData &meta)
{
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), AVSESSION_ERROR, "uri is empty");
    SLOGI("DownloadAndSetCoverImage with title %{public}s",
        AVSessionUtils::GetAnonyTitle(meta.GetTitle().c_str()).c_str());
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    bool ret = DownloadImage(uri, pixelMap);
    SLOGI("DownloadAndSetCoverImage with ret %{public}d, %{public}d", static_cast<int>(ret),
        static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DownloadAndSetCoverImage success and ResetToBaseMeta");
        meta.ResetToBaseMeta();
        meta.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
        return AVSESSION_SUCCESS;
    }
    return AVSESSION_ERROR;
}

int32_t AVSessionNdkUtils::DownloadAndSetCastIcon(const std::string &uri,
    std::shared_ptr<AVMediaDescription> &description)
{
    CHECK_AND_RETURN_RET_LOG(!uri.empty() && description != nullptr, AVSESSION_ERROR,
        "uri is empty or description is nullptr");
    SLOGI("DownloadAndSetCastIcon with title %{public}s", description->GetTitle().c_str());
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    bool ret = DownloadImage(uri, pixelMap);
    SLOGI("DownloadAndSetCastIcon with ret %{public}d, %{public}d",
        static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DownloadAndSetCastIcon success");
        description->SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
        return AVSESSION_SUCCESS;
    }
    return AVSESSION_ERROR;
}

bool AVSessionNdkUtils::DownloadImage(const std::string &uri, std::shared_ptr<Media::PixelMap>& pixelMap)
{
    std::vector<std::uint8_t> imgBuffer(0);
    if (CurlSetRequestOptions(uri, imgBuffer) == true) {
        std::uint8_t* buffer = (std::uint8_t*) calloc(imgBuffer.size(), sizeof(uint8_t));
        if (buffer == nullptr) {
            SLOGE("buffer malloc fail");
            free(buffer);
            return false;
        }
        std::copy(imgBuffer.begin(), imgBuffer.end(), buffer);
        uint32_t errorCode = 0;
        Media::SourceOptions opts;
        SLOGD("DownloadImage get size %{public}d", static_cast<int>(imgBuffer.size()));
        auto imageSource = Media::ImageSource::CreateImageSource(buffer, imgBuffer.size(), opts, errorCode);
        free(buffer);
        if (errorCode || !imageSource) {
            SLOGE("DownloadImage create imageSource fail: %{public}u", errorCode);
            return false;
        }
        Media::DecodeOptions decodeOpts;
        pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        if (errorCode || pixelMap == nullptr) {
            SLOGE("DownloadImage creatPix fail: %{public}u, %{public}d",
                errorCode, static_cast<int>(pixelMap != nullptr));
            return false;
        }
        return true;
    }
    return false;
}

bool AVSessionNdkUtils::CurlSetRequestOptions(const std::string &uri, std::vector<std::uint8_t> &imgBuffer)
{
    CURL *easyHandle_ = curl_easy_init();
    if (easyHandle_) {
        // set request options
        curl_easy_setopt(easyHandle_, CURLOPT_URL, uri.c_str());
        curl_easy_setopt(easyHandle_, CURLOPT_CONNECTTIMEOUT, AVSessionNdkUtils::TIME_OUT_SECOND);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(easyHandle_, CURLOPT_CAINFO, "/etc/ssl/certs/" "cacert.pem");
        curl_easy_setopt(easyHandle_, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEFUNCTION, AVSessionNdkUtils::WriteCallback);
        curl_easy_setopt(easyHandle_, CURLOPT_WRITEDATA, &imgBuffer);

        // perform request
        CURLcode res = curl_easy_perform(easyHandle_);
        if (res != CURLE_OK) {
            SLOGI("CurlSetRequestOptions curl easy_perform failure: %{public}s\n", curl_easy_strerror(res));
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return false;
        } else {
            int64_t httpCode = 0;
            curl_easy_getinfo(easyHandle_, CURLINFO_RESPONSE_CODE, &httpCode);
            SLOGI("CurlSetRequestOptions Http result " "%{public}" PRId64, httpCode);
            CHECK_AND_RETURN_RET_LOG(httpCode < AVSessionNdkUtils::HTTP_ERROR_CODE, false, "recv Http ERROR");
            curl_easy_cleanup(easyHandle_);
            easyHandle_ = nullptr;
            return true;
        }
    }
    return false;
}

size_t AVSessionNdkUtils::WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb,
    std::vector<std::uint8_t> *imgBuffer)
{
    size_t realsize = 0;
    if (ptr == nullptr || size == realsize || nmemb == realsize || imgBuffer == nullptr) {
        SLOGE("WriteCallback parameter is invaild");
        return realsize;
    }
    realsize = size * nmemb;
    imgBuffer->reserve(realsize + imgBuffer->capacity());
    for (size_t i = 0; i < realsize; i++) {
        imgBuffer->push_back(ptr[i]);
    }
    return realsize;
}

AVSessionDownloadHandler &AVSessionDownloadHandler::GetInstance()
{
    static AVSessionDownloadHandler aVSessionDownloadHandler;
    return aVSessionDownloadHandler;
}

AVSessionDownloadHandler::AVSessionDownloadHandler()
{
    SLOGI("AVSessionDownloadHandler construct");
}

AVSessionDownloadHandler::~AVSessionDownloadHandler()
{
    SLOGI("AVSessionDownloadHandler destroy handlerClear");
    std::lock_guard<std::mutex> lockGuard(handlerLock_);
    handler_ = nullptr;
}

bool AVSessionDownloadHandler::AVSessionDownloadPostTask(const Callback &callback, const std::string &name,
    int64_t delayTime)
{
    SLOGD("AVSessionDownloadImagePostTask ProxyPostTask: %{public}s", name.c_str());
    std::lock_guard<std::mutex> lockGuard(handlerLock_);
    if (handler_ == nullptr) {
        SLOGI("AVSessionDownloadHandler create new: %{public}s", name.c_str());
        auto runner = AppExecFwk::EventRunner::Create("OS_AVSessionDownloadHdl");
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    CHECK_AND_RETURN_RET_LOG(handler_ != nullptr, false, "handler_ is nullptr");
    return handler_->PostTask(callback, name, delayTime);
}

void AVSessionDownloadHandler::AVSessionDownloadRemoveTask(const std::string &name)
{
    SLOGI("AVSessionEventHandlerRemove:%{public}s", name.c_str());
    std::lock_guard<std::mutex> lockGuard(handlerLock_);
    if (handler_) {
        handler_->RemoveTask(name);
    }
}

void AVSessionDownloadHandler::AVSessionDownloadRemoveHandler()
{
    SLOGI("AVSessionDownloadHandler RemoveEventHandler");
    std::lock_guard<std::mutex> lockGuard(handlerLock_);
    handler_ = nullptr;
}
}