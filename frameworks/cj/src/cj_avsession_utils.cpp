/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avsession_utils.h"

#include "securec.h"
#include <cstdlib>
#include <vector>

#include "int_wrapper.h"
#include "double_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"
#include "long_wrapper.h"
#include "array_wrapper.h"
#include "want_params_wrapper.h"
#include "pixel_map_impl.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "cj_avsession_media_description.h"

namespace OHOS::AVSession {

/* WantParas <=> CArray<CParameters> ========================*/

const char *FD = "FD";
const char *REMOTE_OBJECT = "RemoteObject";
const char *TYPE_PROPERTY = "type";
const char *VALUE_PROPERTY = "value";
constexpr int32_t I32_TYPE = 1;
constexpr int32_t DOUBLE_TYPE = 11;
constexpr int32_t STR_TYPE = 0;
constexpr int32_t BOOL_TYPE = 3;
constexpr int32_t FD_TYPE = 4;
constexpr int32_t STR_PTR_TYPE = 5;
constexpr int32_t I32_PTR_TYPE = 6;
constexpr int32_t I64_PTR_TYPE = 7;
constexpr int32_t BOOL_PTR_TYPE = 8;
constexpr int32_t DOUBLE_PTR_TYPE = 9;
constexpr int32_t FD_PTR_TYPE = 10;
constexpr int32_t NONE_VALUE = -1;

using WantParams = OHOS::AAFwk::WantParams;

void charPtrToVector(char **charPtr, int size, std::vector<std::string> &result)
{
    for (int i = 0; i < size; i++) {
        result.push_back(std::string(charPtr[i]));
    }
}

void SetFdData(std::string key, int *value, WantParams &wantP)
{
    WantParams wp;
    wp.SetParam(TYPE_PROPERTY, OHOS::AAFwk::String::Box(FD));
    wp.SetParam(VALUE_PROPERTY, OHOS::AAFwk::Integer::Box(*value));
    sptr<OHOS::AAFwk::IWantParams> pWantParams = OHOS::AAFwk::WantParamWrapper::Box(wp);
    wantP.SetParam(key, pWantParams);
}

bool InnerSetWantParamsArrayString(
    const std::string &key, const std::vector<std::string> &value, WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::String::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayInt(const std::string &key, const std::vector<int> &value,
    WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IInteger);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Integer::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayLong(const std::string &key, const std::vector<long> &value,
    WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_ILong);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Long::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayBool(const std::string &key, const std::vector<bool> &value,
    WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IBoolean);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Boolean::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

bool InnerSetWantParamsArrayDouble(
    const std::string &key, const std::vector<double> &value, WantParams &wantParams)
{
    size_t size = value.size();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IDouble);
    if (ao != nullptr) {
        for (size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Double::Box(value[i]));
        }
        wantParams.SetParam(key, ao);
        return true;
    } else {
        return false;
    }
}

void InnerSetWantParamsArrayFD(CParameters* head, int64_t size, WantParams &wantParams)
{
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IWantParams);
    if (ao != nullptr) {
        for (size_t i = 0; i < static_cast<size_t>(size); i++) {
            WantParams wp;
            SetFdData(std::string(head->key), static_cast<int *>(head->value) + i, wp);
            wp.DumpInfo(0);
            ao->Set(i, OHOS::AAFwk::WantParamWrapper::Box(wp));
        }
        wantParams.SetParam(std::string(head->key), ao);
    }
    return;
}

void SetDataParameters(const CArray& parameters, WantParams &wantP)
{
    for (int i = 0; i < parameters.size; i++) {
        auto head = reinterpret_cast<CParameters*>(parameters.head) + i;
        auto key = std::string(head->key);
        if (head->valueType == I32_TYPE) { // int32_t
            wantP.SetParam(key, OHOS::AAFwk::Integer::Box(*static_cast<int32_t *>(head->value)));
        } else if (head->valueType == DOUBLE_TYPE) { // double
            wantP.SetParam(key, OHOS::AAFwk::Double::Box(*static_cast<double *>(head->value)));
        } else if (head->valueType == STR_TYPE) { // std::string
            wantP.SetParam(key, OHOS::AAFwk::String::Box(std::string(static_cast<char *>(head->value))));
        } else if (head->valueType == BOOL_TYPE) { // bool
            wantP.SetParam(key, OHOS::AAFwk::Boolean::Box(*static_cast<bool *>(head->value)));
        } else if (head->valueType == FD_TYPE) { // "FD"
            SetFdData(key, static_cast<int *>(head->value), wantP);
        } else if (head->valueType == STR_PTR_TYPE) { // char**
            char **strPtr = static_cast<char **>(head->value);
            std::vector<std::string> strVec;
            charPtrToVector(strPtr, head->size, strVec);
            InnerSetWantParamsArrayString(key, strVec, wantP);
        } else if (head->valueType == I32_PTR_TYPE) { // int32_t*
            int *intArr = static_cast<int *>(head->value);
            std::vector<int> intVec(intArr, intArr + head->size);
            InnerSetWantParamsArrayInt(key, intVec, wantP);
        } else if (head->valueType == I64_PTR_TYPE) { // int64_t*
            long *longArr = static_cast<long *>(head->value);
            std::vector<long> longVec(longArr, longArr + head->size);
            InnerSetWantParamsArrayLong(key, longVec, wantP);
        } else if (head->valueType == BOOL_PTR_TYPE) { // bool*
            bool *boolArr = static_cast<bool *>(head->value);
            std::vector<bool> boolVec(boolArr, boolArr + head->size);
            InnerSetWantParamsArrayBool(key, boolVec, wantP);
        } else if (head->valueType == DOUBLE_PTR_TYPE) { // double*
            double *doubleArr = static_cast<double *>(head->value);
            std::vector<double> doubleVec(doubleArr, doubleArr + head->size);
            InnerSetWantParamsArrayDouble(key, doubleVec, wantP);
        } else if (head->valueType == FD_PTR_TYPE) { // FD*
            InnerSetWantParamsArrayFD(head, head->size, wantP);
        } else {
            SLOGE("Wrong type!");
        }
    }
}

char *MallocCString(const std::string &origin)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

char *MallocCString(const std::string &origin, int32_t &code)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        code = ERR_NO_MEMORY;
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

// WantParameters -> CArrParameters
int32_t InnerWrapWantParamsString(const WantParams &wantParams, CParameters *p)
{
    int ret = CJNO_ERROR;
    auto value = wantParams.GetParam(p->key);
    AAFwk::IString *ao = AAFwk::IString::Query(value);
    if (ao == nullptr) {
        SLOGE("No value");
        p->valueType = NONE_VALUE;
        return CJNO_ERROR;
    }
    std::string natValue = OHOS::AAFwk::String::Unbox(ao);
    p->value = MallocCString(natValue, ret);
    p->size = static_cast<int64_t>(natValue.length()) + 1;
    p->valueType = STR_TYPE;
    return ret;
}

template <class TBase, class T, class NativeT>
int32_t InnerWrapWantParamsT(const WantParams &wantParams, CParameters *p)
{
    auto value = wantParams.GetParam(p->key);
    TBase *ao = TBase::Query(value);
    if (ao == nullptr) {
        SLOGE("No value");
        p->valueType = NONE_VALUE;
        return CJNO_ERROR;
    }
    NativeT natValue = T::Unbox(ao);
    NativeT *ptr = static_cast<NativeT *>(malloc(sizeof(NativeT)));
    if (ptr == nullptr) {
        return ERR_NO_MEMORY;
    }
    *ptr = natValue;
    p->value = static_cast<void*>(ptr);
    p->size = sizeof(NativeT);
    return CJNO_ERROR;
}

int32_t InnerWrapWantParamsUnboxArrayString(sptr<AAFwk::IArray>& ao, int index, char*& strPtr)
{
    sptr<AAFwk::IInterface> iface = nullptr;
    if (ao->Get(index, iface) == ERR_OK) {
        AAFwk::IString *iValue = AAFwk::IString::Query(iface);
        if (iValue != nullptr) {
            auto val = AAFwk::String::Unbox(iValue);
            strPtr = MallocCString(val);
            if (strPtr == nullptr) { return ERR_NO_MEMORY; }
        }
    }
    return CJNO_ERROR;
}

int32_t InnerWrapWantParamsArrayString(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        SLOGE("fail to get length");
        return AVSESSION_ERROR;
    }
    if (size == 0) {
        return AVSESSION_ERROR;
    }
    char **arrP = static_cast<char **>(malloc(sizeof(char *) * size));
    if (arrP == nullptr) {
        SLOGE("fail to malloc");
        return ERR_NO_MEMORY;
    }
    int ret = CJNO_ERROR;
    for (long i = 0; i < size; i++) {
        ret = InnerWrapWantParamsUnboxArrayString(ao, i, arrP[i]);
        if (ret != CJNO_ERROR) { return ret; }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
    return CJNO_ERROR;
}

void ClearParametersPtr(CParameters *&ptr, int count, bool isKey)
{
    CParameters *p = ptr;
    for (int i = 0; i < count; i++) {
        free(p[i].key);
        free(p[i].value);
        p[i].key = nullptr;
        p[i].value = nullptr;
    }
    if (!isKey) {
        free(p[count].key);
        p[count].key = nullptr;
    }
    free(ptr);
    ptr = nullptr;
}

template <class TBase, class T, class NativeT>
int32_t InnerWrapWantParamsArrayT(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        SLOGE("fail to get length");
        return AVSESSION_ERROR;
    }
    if (size == 0) {
        return AVSESSION_ERROR;
    }
    NativeT *arrP = static_cast<NativeT *>(malloc(sizeof(NativeT) * size));
    if (arrP == nullptr) {
        SLOGE("fail to malloc");
        return ERR_NO_MEMORY;
    }
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == ERR_OK) {
            TBase *iValue = TBase::Query(iface);
            if (iValue != nullptr) {
                arrP[i] = T::Unbox(iValue);
            }
        }
    }
    p->size = size;
    p->value = static_cast<void *>(arrP);
    return CJNO_ERROR;
}

int32_t GetFDValue(const WantParams &wantParams, std::string key, int *ptr)
{
    auto value = wantParams.GetParam(key);
    AAFwk::IWantParams *o = AAFwk::IWantParams::Query(value);
    if (o == nullptr) {
        SLOGE("No value");
        return CJNO_ERROR;
    }
    AAFwk::WantParams wp = AAFwk::WantParamWrapper::Unbox(o);
    value = wp.GetParam(VALUE_PROPERTY);
    AAFwk::IInteger *ao = AAFwk::IInteger::Query(value);
    if (ao == nullptr) {
        SLOGE("No value");
        return CJNO_ERROR;
    }
    *ptr = OHOS::AAFwk::Integer::Unbox(ao);
    return CJNO_ERROR;
}

int32_t InnerWrapWantParamsFd(const WantParams &wantParams, CParameters *p)
{
    int *ptr = static_cast<int *>(malloc(sizeof(int)));
    if (ptr == nullptr) {
        return ERR_NO_MEMORY;
    }
    int error = GetFDValue(wantParams, std::string(p->key), ptr);
    if (error != CJNO_ERROR) {
        free(ptr);
        return error;
    }
    p->value = static_cast<void*>(ptr);
    p->size = sizeof(int32_t);
    p->valueType = FD_TYPE;
    return CJNO_ERROR;
}

int32_t InnerWrapWantParamsArrayFd(sptr<AAFwk::IArray> &ao, CParameters *p)
{
    long size = 0;
    if (ao->GetLength(size) != ERR_OK) {
        SLOGE("fail to get length");
        return AVSESSION_ERROR;
    }
    if (size == 0) {
        return AVSESSION_ERROR;
    }
    int *arrP = static_cast<int *>(malloc(sizeof(int) * size));
    if (arrP == nullptr) {
        SLOGE("fail to malloc");
        return ERR_NO_MEMORY;
    }
    for (long i = 0; i < size; i++) {
        sptr<AAFwk::IInterface> iface = nullptr;
        if (ao->Get(i, iface) == ERR_OK) {
            AAFwk::IWantParams *iValue = AAFwk::IWantParams::Query(iface);
            if (iValue == nullptr) {
                free(arrP);
                return AVSESSION_ERROR;
            }
            WantParams wantP = AAFwk::WantParamWrapper::Unbox(iValue);
            int ret = GetFDValue(wantP, std::string(p->key), arrP + i);
            if (ret != CJNO_ERROR) {
                free(arrP);
                return ret;
            }
        }
    }
    p->size = size;
    p->value = arrP;
    p->valueType = FD_PTR_TYPE;
    return CJNO_ERROR;
}

int32_t InnerWrapWantParamsArray(const WantParams &wantParams, sptr<AAFwk::IArray> &ao, CParameters *p)
{
    SLOGI("%{public}s called. key=%{public}s", __func__, p->key);
    if (AAFwk::Array::IsStringArray(ao)) {
        p->valueType = STR_PTR_TYPE;
        return InnerWrapWantParamsArrayString(ao, p);
    } else if (AAFwk::Array::IsBooleanArray(ao)) {
        p->valueType = BOOL_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IBoolean, AAFwk::Boolean, bool>(ao, p);
    } else if (AAFwk::Array::IsIntegerArray(ao)) {
        p->valueType = I32_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IInteger, AAFwk::Integer, int>(ao, p);
    } else if (AAFwk::Array::IsLongArray(ao)) {
        p->valueType = I64_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::ILong, AAFwk::Long, int64_t>(ao, p);
    } else if (AAFwk::Array::IsDoubleArray(ao)) {
        p->valueType = DOUBLE_PTR_TYPE;
        return InnerWrapWantParamsArrayT<AAFwk::IDouble, AAFwk::Double, double>(ao, p);
    } else {
        p->valueType = FD_PTR_TYPE;
        return InnerWrapWantParamsArrayFd(ao, p);
    }
}

void ParseParameters(const AAFwk::WantParams &wantP, CArray &cArray, int32_t &code)
{
    std::map<std::string, sptr<OHOS::AAFwk::IInterface>> paramsMap = wantP.GetParams();
    int count = 0;
    auto size = static_cast<int64_t>(paramsMap.size());
    SLOGD("paramsMap size = %{public}" PRId64, size);
    if (size == 0) {
        return;
    }
    cArray.head = malloc(sizeof(CParameters) * size);
    if (cArray.head == nullptr) {
        code = ERR_NO_MEMORY;
        return;
    }
    cArray.size = size;
    for (auto iter = paramsMap.begin(); iter != paramsMap.end(); iter++) {
        auto ptr = reinterpret_cast<CParameters *>(cArray.head) + count;
        ptr->key = MallocCString(iter->first);
        if (ptr->key == nullptr) {
            code = ERR_NO_MEMORY;
            return ClearParametersPtr(reinterpret_cast<CParameters *&>(cArray.head), count, true);
        }
        ptr->value = nullptr;
        ptr->size = 0;
        if (AAFwk::IString::Query(iter->second) != nullptr) {
            code = InnerWrapWantParamsString(wantP, ptr);
        } else if (AAFwk::IBoolean::Query(iter->second) != nullptr) {
            ptr->valueType = BOOL_TYPE;
            code = InnerWrapWantParamsT<AAFwk::IBoolean, AAFwk::Boolean, bool>(wantP, ptr);
        } else if (AAFwk::IInteger::Query(iter->second) != nullptr) {
            ptr->valueType = I32_TYPE;
            code = InnerWrapWantParamsT<AAFwk::IInteger, AAFwk::Integer, int>(wantP, ptr);
        } else if (AAFwk::IDouble::Query(iter->second) != nullptr) {
            ptr->valueType = DOUBLE_TYPE;
            code = InnerWrapWantParamsT<AAFwk::IDouble, AAFwk::Double, double>(wantP, ptr);
        } else if (AAFwk::IWantParams::Query(iter->second) != nullptr) {
            code = InnerWrapWantParamsFd(wantP, ptr);
        } else if (AAFwk::IArray::Query(iter->second) != nullptr) {
            AAFwk::IArray *ao = AAFwk::IArray::Query(iter->second);
            sptr<AAFwk::IArray> array(ao);
            code = InnerWrapWantParamsArray(wantP, array, ptr);
        }
        if (code == ERR_NO_MEMORY || code == AVSESSION_ERROR) {
            return ClearParametersPtr(reinterpret_cast<CParameters *&>(cArray.head), count, true);
        }
        count++;
    }
}

/* Converter ================================================*/
template<class T>
int32_t CJConverterMalloc(T*& obj, int64_t size)
{
    if (size <= 0) {
        obj = nullptr;
        return CJNO_ERROR;
    }
    obj = static_cast<T *>(malloc(sizeof(T) * size));
    if (obj == nullptr) {
        return ERR_NO_MEMORY;
    }
    return CJNO_ERROR;
}

using Step = std::function<int32_t()>;
class CJUtilsChainCall {
public:

    void addStep(Step step)
    {
        steps.push_back(step);
    }

    static int32_t runSteps(std::vector<Step> &funcs)
    {
        int code = CJNO_ERROR;
        for (auto& step: funcs) {
            int32_t code = step();
            if (code != CJNO_ERROR) {
                return code;
            }
        }
        return code;
    }

    int32_t run()
    {
        int code = CJNO_ERROR;
        for (auto& step: steps) {
            int32_t code = step();
            if (code != CJNO_ERROR) {
                return code;
            }
        }
        return code;
    }

    private:
        std::vector<Step> steps;
};


/* Native to Cangjie*/
int32_t convertNativeToCJStruct(const AVCallState& native, CAVCallState& cj)
{
    cj.state = native.GetAVCallState();
    cj.muted = native.IsAVCallMuted();
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const AVCallMetaData& native, CAVCallMetaData& cj)
{
    std::vector<Step> steps;
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetName(), cj.name); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetPhoneNumber(), cj.phoneNumber); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetMediaImage(), cj.avatar); });
    return CJUtilsChainCall::runSteps(steps);
}

int32_t convertNativeToCJStruct(const AVMetaData& native, CAVMetaData& cj)
{
    std::vector<Step> steps;
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAssetId(), cj.assetId); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetTitle(), cj.title); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetArtist(), cj.artist); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAuthor(), cj.author); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAVQueueName(), cj.avQueueName); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAVQueueId(), cj.avQueueId); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAlbum(), cj.album); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetWriter(), cj.writer); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetComposer(), cj.composer); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetSubTitle(), cj.subtitle); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetDescription(), cj.description); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetLyric(), cj.lyric); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetPreviousAssetId(), cj.previousAssetId); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetNextAssetId(), cj.nextAssetId); });
    int32_t errCode = CJUtilsChainCall::runSteps(steps);
    if (errCode != CJNO_ERROR) {
        return errCode;
    }
    cj.duration = native.GetDuration();
    cj.publishDate = int64_t(native.GetPublishDate());
    cj.skipIntervals = native.GetSkipIntervals();
    cj.filter = native.GetFilter();
    cj.displayTags = native.GetDisplayTags();
    cj.mediaLength = native.GetMediaLength();
    cj.avQueueLength = native.GetAVQueueLength();

    if (native.GetMetaMask() == AVMetaData::META_KEY_AVQUEUE_IMAGE) {
        errCode = convertNativeToCJStruct(native.GetAVQueueImage(), cj.avQueueImage);
    } else {
        errCode = convertNativeToCJStruct(native.GetAVQueueImageUri(), cj.avQueueImage);
    }
    if (errCode != CJNO_ERROR) { return errCode; }
    if (native.GetMetaMask() == AVMetaData::META_KEY_MEDIA_IMAGE) {
        errCode = convertNativeToCJStruct(native.GetMediaImage(), cj.mediaImage);
    } else {
        errCode = convertNativeToCJStruct(native.GetMediaImageUri(), cj.mediaImage);
    }
    if (errCode != CJNO_ERROR) { return errCode; }
    return convertNativeToCJStruct(native.GetDrmSchemes(), cj.drmSchemes);
}

int32_t convertNativeToCJStruct(const std::shared_ptr<AVSessionPixelMap>& native, int64_t& cj)
{
    cj = Media::PixelMapImpl(AVSessionPixelMapAdapter::ConvertFromInner(native)).GetID();
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const std::shared_ptr<AVSessionPixelMap>& native, StringPixelMapParameter& cj)
{
    cj.pixelMap = Media::PixelMapImpl(AVSessionPixelMapAdapter::ConvertFromInner(native)).GetID();
    cj.kind = 1;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const std::string& native, StringPixelMapParameter& cj)
{
    convertNativeToCJStruct(native, cj.string);
    cj.kind = 0;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const std::vector<std::string>& native, CArray& cj)
{
    int32_t ret = CJNO_ERROR;
    char** &cjArrHead = reinterpret_cast<char**&>(cj.head);
    ret = CJConverterMalloc<char*>(cjArrHead, native.size());
    if (ret != CJNO_ERROR) {
        return ret;
    }
    cj.size = native.size();
    for (uint32_t i = 0; i < native.size(); i++) {
        int32_t errCode = convertNativeToCJStruct(native[i], cjArrHead[i]);
        if (errCode != CJNO_ERROR) {
            return errCode;
        }
    }
    return ret;
}

int32_t convertNativeToCJStruct(const std::string& native, char*& cj)
{
    int32_t ret = CJNO_ERROR;
    ret = CJConverterMalloc<char>(cj, native.length() + 1);
    if (ret != CJNO_ERROR) {
        return ret;
    }
    if (strcpy_s(cj, native.length() + 1, native.c_str()) != 0) {
        return AVSESSION_ERROR;
    }
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const OutputDeviceInfo& native, COutputDeviceInfo& cj)
{
    int32_t ret = CJNO_ERROR;
    CDeviceInfo* &cjArrHead = reinterpret_cast<CDeviceInfo*&>(cj.devices.head);
    ret = CJConverterMalloc<CDeviceInfo>(cjArrHead, native.deviceInfos_.size());
    if (ret != CJNO_ERROR) {
        return ret;
    }
    cj.devices.size = native.deviceInfos_.size();
    for (uint32_t i = 0; i < native.deviceInfos_.size(); i++) {
        convertNativeToCJStruct(native.deviceInfos_[i], cjArrHead[i]);
    }
    return ret;
}

int32_t convertNativeToCJStruct(const DeviceInfo& native, CDeviceInfo& cj)
{
    std::vector<Step> steps;
    steps.push_back([&]() { return convertNativeToCJStruct(native.deviceId_, cj.deviceId); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.deviceName_, cj.deviceName); });
    steps.push_back([&]() {
        return convertNativeToCJStruct(native.supportedDrmCapabilities_, cj.supportedDrmCapabilities);
    });
    int32_t errCode = CJUtilsChainCall::runSteps(steps);
    if (errCode != CJNO_ERROR) {
        return errCode;
    }
    cj.castCategory = native.castCategory_;
    cj.deviceType = native.deviceType_;
    cj.supportedProtocols = native.supportedProtocols_;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const int64_t& native, int64_t& cj)
{
    cj = native;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const bool& native, bool& cj)
{
    cj = native;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const std::vector<int32_t>& native, CArray&cj)
{
    int32_t ret = CJNO_ERROR;
    int32_t* &cjArrHead = reinterpret_cast<int32_t*&>(cj.head);
    ret = CJConverterMalloc<int32_t>(cjArrHead, native.size());
    if (ret != CJNO_ERROR) {
        return ret;
    }
    cj.size = native.size();
    for (uint32_t i = 0; i < native.size(); i++) {
        cjArrHead[i] = native[i];
    }
    return ret;
}

int32_t convertNativeToCJStruct(const std::vector<AVQueueItem>& native, CArray&cj)
{
    int32_t ret = CJNO_ERROR;
    CAVQueueItem* &cjArrHead = reinterpret_cast<CAVQueueItem*&>(cj.head);
    ret = CJConverterMalloc<CAVQueueItem>(cjArrHead, native.size());
    if (ret != CJNO_ERROR) {
        return ret;
    }
    cj.size = native.size();
    for (uint32_t i = 0; i < native.size(); i++) {
        int32_t errCode = convertNativeToCJStruct(native[i], cjArrHead[i]);
        if (errCode != CJNO_ERROR) {
            return errCode;
        }
    }
    return ret;
}

int32_t convertNativeToCJStruct(const AVQueueItem& native, CAVQueueItem& cj)
{
    cj.itemId = native.GetItemId();
    return convertNativeToCJStruct(*native.GetDescription(), cj.description);
}

int32_t convertNativeToCJStruct(const AVMediaDescription& native, CAVMediaDescription& cj)
{
    std::vector<Step> steps;
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetMediaId(), cj.mediaId); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetTitle(), cj.title); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetSubtitle(), cj.subtitle); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetDescription(), cj.description); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetMediaUri(), cj.mediaUri); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetMediaType(), cj.mediaType); });
    steps.push_back([&]() { return convertNativeToCJStruct(*native.GetExtras(), cj.extras); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAlbumTitle(), cj.albumTitle); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAlbumCoverUri(), cj.albumCoverUri); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetLyricContent(), cj.lyricContent); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetLyricUri(), cj.lyricUri); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetArtist(), cj.artist); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetFdSrc(), cj.fdSrc); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetDrmScheme(), cj.drmScheme); });
    steps.push_back([&]() { return convertNativeToCJStruct(native.GetAppName(), cj.appName); });
    int32_t errCode = CJUtilsChainCall::runSteps(steps);
    if (errCode != CJNO_ERROR) {
        return errCode;
    }
    FFI_MD_HELPER->GetMediaDescriptionDataSrc(cj);
    cj.mediaSize = native.GetMediaSize();
    cj.duration = native.GetDuration();
    cj.startPosition = native.GetStartPosition();
    cj.creditsPosition = native.GetCreditsPosition();
    FFI_MD_HELPER->GetMediaDescriptionDisplayTags(cj);

    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const AAFwk::WantParams& native, CArray& cj)
{
    int32_t errCode = CJNO_ERROR;
    ParseParameters(native, cj, errCode);
    return errCode;
}

int32_t convertNativeToCJStruct(const AVFileDescriptor& native, CAVFileDescriptor& cj)
{
    cj.fd = native.fd_;
    cj.offset = native.offset_;
    cj.length = native.length_;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const AVPlaybackState::Position& native, CPlaybackPosition& cj)
{
    cj.elapsedTime = native.elapsedTime_;
    cj.updateTime = native.updateTime_;
    return CJNO_ERROR;
}

int32_t convertNativeToCJStruct(const AVPlaybackState& native, CAVPlaybackState& cj)
{
    cj.state = native.GetState();
    cj.speed = native.GetSpeed();
    convertNativeToCJStruct(native.GetPosition(), cj.position);
    cj.bufferedTime = native.GetBufferedTime();
    cj.loopMode = native.GetLoopMode();
    cj.isFavorite = native.GetFavorite();
    cj.activeItemId = native.GetActiveItemId();
    cj.volume = native.GetVolume();
    cj.maxVolume = native.GetMaxVolume();
    cj.muted = native.GetMuted();
    cj.duration = native.GetDuration();
    cj.videoWidth = native.GetVideoWidth();
    cj.videoHeight = native.GetVideoHeight();
    return convertNativeToCJStruct(*native.GetExtras(), cj.extras);
}

/* Cangjie to Native*/

int32_t convertCJStructToNative(const CArray& cj, AAFwk::WantParams &native)
{
    SetDataParameters(cj, native);
    return CJNO_ERROR;
}

int32_t convertCJStructToNative(const CAVMetaData& cj, AVMetaData &native)
{
    int32_t ret = CJNO_ERROR;
    native.SetAssetId(std::string(cj.assetId));
    native.SetTitle(std::string(cj.title));
    native.SetArtist(std::string(cj.artist));
    native.SetAuthor(std::string(cj.author));
    native.SetAVQueueName(std::string(cj.avQueueName));
    native.SetAVQueueId(std::string(cj.avQueueId));
    if (cj.avQueueImage.kind == 0) {
        native.SetAVQueueImageUri(std::string(cj.avQueueImage.string));
    } else {
        auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(
            cj.avQueueImage.pixelMap)->GetRealPixelMap();
        native.SetAVQueueImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    }
    native.SetAlbum(std::string(cj.album));
    native.SetWriter(std::string(cj.writer));
    native.SetComposer(std::string(cj.composer));
    native.SetDuration(cj.duration);
    if (cj.mediaImage.kind == 0) {
        native.SetMediaImageUri(std::string(cj.mediaImage.string));
    } else {
        auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(
            cj.mediaImage.pixelMap)->GetRealPixelMap();
        native.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    }
    native.SetPublishDate(cj.publishDate);
    native.SetSubTitle(std::string(cj.subtitle));
    native.SetDescription(std::string(cj.description));
    native.SetLyric(std::string(cj.lyric));
    native.SetPreviousAssetId(std::string(cj.previousAssetId));
    native.SetNextAssetId(std::string(cj.nextAssetId));
    native.SetFilter(cj.filter);

    std::vector<std::string> drmS;
    ret = convertCJStructToNative(cj.drmSchemes, drmS);
    if (ret != CJNO_ERROR) {
        return CJNO_ERROR;
    }
    native.SetDrmSchemes(drmS);

    native.SetSkipIntervals(cj.skipIntervals);
    native.SetDisplayTags(cj.displayTags);
    native.SetMediaLength(cj.mediaLength);
    native.SetAVQueueLength(cj.avQueueLength);
    return ret;
}

int32_t convertCJStructToNative(const CArray& cj, std::vector<std::string>& native)
{
    if (cj.size == 0) {
        return CJNO_ERROR;
    }
    auto ptr = reinterpret_cast<char**>(cj.head);
    for (int i = 0; i < cj.size; i++) {
        native.push_back(std::string(ptr[i]));
    }
    return CJNO_ERROR;
}

int32_t convertCJStructToNative(const CAVCallMetaData& cj, AVCallMetaData & native)
{
    native.SetName(std::string(cj.name));
    native.SetPhoneNumber(std::string(cj.phoneNumber));
    auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(
            cj.avatar)->GetRealPixelMap();
    native.SetMediaImage(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    return CJNO_ERROR;
}

int32_t convertCJStructToNative(const CAVCallState& cj, AVCallState& native)
{
    native.SetAVCallState(cj.state);
    native.SetAVCallMuted(cj.muted);
    return CJNO_ERROR;
}

int32_t convertCJStructToNative(const CAVPlaybackState& cj, AVPlaybackState& native)
{
    int32_t ret = CJNO_ERROR;
    native.SetState(cj.state);
    native.SetSpeed(cj.speed);
    AVPlaybackState::Position position;
    position.elapsedTime_ = cj.position.elapsedTime;
    position.updateTime_ = cj.position.updateTime;
    native.SetPosition(position);
    native.SetBufferedTime(cj.bufferedTime);
    native.SetLoopMode(cj.loopMode);
    native.SetFavorite(cj.isFavorite);
    native.SetActiveItemId(cj.activeItemId);
    native.SetVolume(cj.volume);
    native.SetMaxVolume(cj.maxVolume);
    native.SetMuted(cj.muted);
    native.SetDuration(cj.duration);
    native.SetVideoWidth(cj.videoWidth);
    native.SetVideoHeight(cj.videoHeight);
    std::shared_ptr<AAFwk::WantParams> wantP;
    ret = convertCJStructToNative(cj.extras, *wantP);
    if (ret != CJNO_ERROR) {
        return ret;
    }
    native.SetExtras(wantP);
    return ret;
}

int32_t convertCJStructToNative(const CArray& cj, std::vector<AVQueueItem>& native)
{
    int32_t ret = CJNO_ERROR;
    auto ptr = reinterpret_cast<CAVQueueItem*>(cj.head);
    for (int i = 0; i < cj.size; i++) {
        AVQueueItem item;
        ret = convertCJStructToNative(ptr[i], item);
        if (ret != CJNO_ERROR) {
            return ret;
        }
        native.push_back(item);
    }
    return ret;
}

int32_t convertCJStructToNative(const CAVQueueItem& cj, AVQueueItem& native)
{
    int32_t ret = CJNO_ERROR;
    native.SetItemId(cj.itemId);
    std::shared_ptr<AVMediaDescription> desc;
    ret = convertCJStructToNative(cj.description, *desc);
    if (ret != CJNO_ERROR) {
        return ret;
    }
    native.SetDescription(desc);
    return ret;
}

int32_t convertCJStructToNative(const CAVMediaDescription& cj, AVMediaDescription& native)
{
    int32_t ret = CJNO_ERROR;
    native.SetMediaId(std::string(cj.mediaId));
    native.SetTitle(std::string(cj.title));
    native.SetSubtitle(std::string(cj.subtitle));
    native.SetDescription(std::string(cj.description));
    native.SetMediaUri(std::string(cj.mediaUri));
    if (cj.mediaImage.kind == 0) {
        native.SetIconUri(std::string(cj.mediaImage.string));
    } else {
        auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(
            cj.mediaImage.pixelMap)->GetRealPixelMap();
        native.SetIcon(AVSessionPixelMapAdapter::ConvertToInner(pixelMap));
    }
    std::shared_ptr<AAFwk::WantParams> wantP;
    ret = convertCJStructToNative(cj.extras, *wantP);
    if (ret != CJNO_ERROR) {
        return ret;
    }
    native.SetExtras(wantP);
    native.SetMediaType(std::string(cj.mediaType));
    native.SetMediaSize(cj.mediaSize);
    native.SetAlbumTitle(std::string(cj.albumTitle));
    native.SetAlbumCoverUri(std::string(cj.albumCoverUri));
    native.SetLyricContent(std::string(cj.lyricContent));
    native.SetLyricUri(std::string(cj.lyricUri));
    native.SetArtist(std::string(cj.artist));
    AVFileDescriptor fdSrc;
    fdSrc.fd_ = cj.fdSrc.fd;
    fdSrc.offset_ = cj.fdSrc.offset;
    fdSrc.length_ = cj.fdSrc.length;
    native.SetFdSrc(fdSrc);
    native.SetDrmScheme(std::string(cj.drmScheme));
    native.SetDuration(cj.duration);
    native.SetStartPosition(cj.startPosition);
    native.SetCreditsPosition(cj.creditsPosition);
    native.SetAppName(std::string(cj.appName));
    FFI_MD_HELPER->SetMediaDescriptionDataSrc(cj);
    FFI_MD_HELPER->SetMediaDescriptionDataSrc(cj);
    return ret;
}

}  // namespace AVSession::OHOS