/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "OHDeviceInfo.h"

int32_t OHDeviceInfo::GetAVCastCategory()
{
    return castCategory_;
}

const std::string& OHDeviceInfo::GetDeviceId()
{
    return deviceId_;
}

const std::string& OHDeviceInfo::GetDeviceName()
{
    return deviceName_;
}

int32_t OHDeviceInfo::GetDeviceType()
{
    return deviceType_;
}

int32_t OHDeviceInfo::GetSupportedProtocols()
{
    return supportedProtocols_;
}

AVSession_OutputDeviceInfo* OHDeviceInfo::ConvertDesc(const OHOS::AVSession::OutputDeviceInfo &outputDeviceInfoVec)
{
    size_t size = outputDeviceInfoVec.deviceInfos_.size();
    if (size == 0) {
        SLOGE("outputDeviceInfoVec is empty");
        return nullptr;
    }
    OHDeviceInfo **deviceInfoPtr = (OHDeviceInfo **)malloc(sizeof(OHDeviceInfo *) * size);
    if (deviceInfoPtr == nullptr) {
        return nullptr;
    }

    AVSession_OutputDeviceInfo *outputDeviceInfoArray =
        (AVSession_OutputDeviceInfo *)malloc(sizeof(AVSession_OutputDeviceInfo));
    if (outputDeviceInfoArray == nullptr) {
        free(deviceInfoPtr);
        deviceInfoPtr = nullptr;
        return nullptr;
    }
    outputDeviceInfoArray->size = 0;
    outputDeviceInfoArray->deviceInfos = nullptr;

    uint32_t index = 0;
    auto it = outputDeviceInfoVec.deviceInfos_.begin();
    for (; it != outputDeviceInfoVec.deviceInfos_.end(); ++it) {
        int32_t castCategory = (*it).castCategory_;
        std::string deviceId = (*it).deviceId_;
        std::string deviceName = (*it).deviceName_;
        int32_t deviceType = (*it).deviceType_;
        int32_t supportedProtocols = (*it).supportedProtocols_;

        deviceInfoPtr[index] =
            (OHDeviceInfo *)(new OHDeviceInfo(castCategory, deviceId, deviceName, deviceType, supportedProtocols));
        if (deviceInfoPtr[index] == nullptr) {
            for (uint32_t j = 0; j < index; ++j) {
                delete deviceInfoPtr[j];
                deviceInfoPtr[j] = nullptr;
            }
            free(deviceInfoPtr);
            deviceInfoPtr = nullptr;
            free(outputDeviceInfoArray);
            outputDeviceInfoArray = nullptr;
            return nullptr;
        }
        index++;
        outputDeviceInfoArray->size = index;
    }

    outputDeviceInfoArray->deviceInfos = (AVSession_DeviceInfo **)deviceInfoPtr;
    return outputDeviceInfoArray;
}

void OHDeviceInfo::DestroyAVSessionOutputDevice(AVSession_OutputDeviceInfo *array)
{
    if (array) {
        for (uint32_t index = 0; index < array->size; index++) {
            OHDeviceInfo *outputDeviceInfo = (OHDeviceInfo *)array->deviceInfos[index];
            delete outputDeviceInfo;
            array->deviceInfos[index] = nullptr;
        }
        free(array->deviceInfos);
        array->deviceInfos = nullptr;
        free(array);
        array = nullptr;
    }
}

AVSession_ErrCode OH_DeviceInfo_GetAVCastCategory(AVSession_DeviceInfo *deviceInfo,
    AVSession_AVCastCategory *aVCastCategory)
{
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceInfo is null");
    CHECK_AND_RETURN_RET_LOG(aVCastCategory != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "aVCastCategory is null");

    OHDeviceInfo* oh_deviceInfo = (OHDeviceInfo *)deviceInfo;
    *aVCastCategory = (AVSession_AVCastCategory)oh_deviceInfo->GetAVCastCategory();
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_DeviceInfo_GetDeviceId(AVSession_DeviceInfo *deviceInfo, char **deviceId)
{
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceInfo is null");
    CHECK_AND_RETURN_RET_LOG(deviceId != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceId is null");

    OHDeviceInfo *oh_deviceInfo = (OHDeviceInfo *)deviceInfo;
    *deviceId = const_cast<char*>((oh_deviceInfo->GetDeviceId()).c_str());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_DeviceInfo_GetDeviceName(AVSession_DeviceInfo *deviceInfo, char **deviceName)
{
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceInfo is null");
    CHECK_AND_RETURN_RET_LOG(deviceName != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceName is null");

    OHDeviceInfo *oh_deviceInfo = (OHDeviceInfo *)deviceInfo;
    *deviceName = const_cast<char*>((oh_deviceInfo->GetDeviceName()).c_str());
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_DeviceInfo_GetDeviceType(AVSession_DeviceInfo *deviceInfo, AVSession_DeviceType *deviceType)
{
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceInfo is null");
    CHECK_AND_RETURN_RET_LOG(deviceType != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceType is null");

    OHDeviceInfo *oh_deviceInfo = (OHDeviceInfo *)deviceInfo;
    *deviceType = (AVSession_DeviceType)oh_deviceInfo->GetDeviceType();
    return AV_SESSION_ERR_SUCCESS;
}

AVSession_ErrCode OH_DeviceInfo_GetSupportedProtocols(AVSession_DeviceInfo *deviceInfo, uint32_t *deviceProtocolType)
{
    CHECK_AND_RETURN_RET_LOG(deviceInfo != nullptr, AV_SESSION_ERR_INVALID_PARAMETER, "deviceInfo is null");
    CHECK_AND_RETURN_RET_LOG(deviceProtocolType != nullptr, AV_SESSION_ERR_INVALID_PARAMETER,
        "deviceProtocolType is null");

    OHDeviceInfo *oh_deviceInfo = (OHDeviceInfo *)deviceInfo;
    *deviceProtocolType = static_cast<uint32_t>(oh_deviceInfo->GetSupportedProtocols());
    return AV_SESSION_ERR_SUCCESS;
}
