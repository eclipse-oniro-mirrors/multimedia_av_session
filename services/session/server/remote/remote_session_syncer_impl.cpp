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

#include <iomanip>
#include <sstream>
#include "avsession_trace.h"
#include "hash_calculator.h"
#include "parcel.h"
#include "remote_session_syncer_impl.h"

namespace OHOS::AVSession {
RemoteSessionSyncerImpl::RemoteSessionSyncerImpl(const std::string& sourceSessionId, const std::string& sourceDevice,
                                                 const std::string& sinkDevice)
    : object_(nullptr), objectStore_(nullptr), sourceSessionId_(sourceSessionId), sourceDevice_(sourceDevice),
    sinkDevice_(sinkDevice)
{
    SLOGI("construct");
}

void RemoteSessionSyncerImpl::OnChanged(const std::string &sessionId, const std::vector<std::string>& keys)
{
    SLOGI("sessionId is %{public}s key is %{public}s", sessionId.c_str(), keys[0].c_str());
    CHECK_AND_RETURN_LOG(objectDataNotifier_ != nullptr, "objectDataNotifier_ is nullptr");
    for (const auto& key : keys) {
        CHECK_AND_RETURN_LOG(categoryMap.count(key) > 0, "key is not exist");
        objectDataNotifier_(categoryMap.at(key), sinkDevice_);
    }
}

void RemoteSessionSyncerImpl::OnChanged(const std::string &name, const std::string &networkId,
                                        const std::string &onlineStatus)
{
    SLOGI("%{public}.6s %{public}s", networkId.c_str(), onlineStatus.c_str());
    CHECK_AND_RETURN_LOG(onlineStatus == "offline", "state is online");
    CHECK_AND_RETURN_LOG(objectDisconnectNotifier_ != nullptr, "objectDataNotifier_ is nullptr");
    objectDisconnectNotifier_(networkId);
}

int32_t RemoteSessionSyncerImpl::Init()
{
    SLOGI("start");
    objectStore_ = DistributedObjectStore::GetInstance("av_session");
    CHECK_AND_RETURN_RET_LOG(objectStore_ != nullptr, AVSESSION_ERROR, "objectStore_ is nullptr");

    std::string object = sourceSessionId_ + sourceDevice_ + sinkDevice_;
    HashCalculator hashCalculator;
    CHECK_AND_RETURN_RET_LOG(hashCalculator.Init() == AVSESSION_SUCCESS, AVSESSION_ERROR, "hash init failed");
    CHECK_AND_RETURN_RET_LOG(hashCalculator.Update(std::vector<uint8_t>(object.begin(), object.end())) ==
                             AVSESSION_SUCCESS, AVSESSION_ERROR, "hash update failed");
    std::vector<uint8_t> hash;
    CHECK_AND_RETURN_RET_LOG(hashCalculator.GetResult(hash) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "hash get result failed");
    std::stringstream stream;
    int32_t width = 2;
    for (const auto& byte : hash) {
        stream << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << static_cast<int>(byte);
    }
    objectName_ = stream.str();
    SLOGI("sourceSessionId is %{public}s, sourceDevice is %{public}s, sinkDevice is %{public}s, object is %{public}s",
          sourceSessionId_.c_str(), sourceDevice_.c_str(), sinkDevice_.c_str(), objectName_.c_str());
    object_ = objectStore_->CreateObject(objectName_);
    CHECK_AND_RETURN_RET_LOG(object_ != nullptr, AVSESSION_ERROR, "object_ is nullptr");
    SLOGI("init object success");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutData(const std::string &key, std::vector<uint8_t> &data)
{
    CHECK_AND_RETURN_RET_LOG(object_ != nullptr, AVSESSION_ERROR, "object is nullptr");
    return object_->PutComplex(key, data) == ObjectStore::SUCCESS ? AVSESSION_SUCCESS : AVSESSION_ERROR;
}

int32_t RemoteSessionSyncerImpl::GetData(const std::string &key, std::vector<uint8_t> &data)
{
    CHECK_AND_RETURN_RET_LOG(object_ != nullptr, AVSESSION_ERROR, "object is nullptr");
    return object_->GetComplex(key, data) == ObjectStore::SUCCESS ? AVSESSION_SUCCESS : AVSESSION_ERROR;
}

int32_t RemoteSessionSyncerImpl::PutAVMetaData(const AVMetaData& metaData)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutAVMetaData");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(metaData.Marshalling(data), AVSESSION_ERROR, "metaData Marshalling error");
    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(METADATA_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR, "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetAVMetaData(AVMetaData& metaData)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(METADATA_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR, "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);
    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");
    AVMetaData *data = AVMetaData::Unmarshalling(parcelData);
    CHECK_AND_RETURN_RET_LOG(data != nullptr, AVSESSION_ERROR, "Unmarshalling error");
    metaData = *data;
    delete data;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutAVPlaybackState(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutAVPlaybackState");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(state.Marshalling(data), AVSESSION_ERROR, "state Marshalling error");
    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(PLAYBACK_STATE_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetAVPlaybackState(AVPlaybackState& state)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(PLAYBACK_STATE_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);
    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");
    AVPlaybackState *data = AVPlaybackState::Unmarshalling(parcelData);
    CHECK_AND_RETURN_RET_LOG(data != nullptr, AVSESSION_ERROR, "Unmarshalling error");
    state = *data;
    delete data;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutControlCommand(const AVControlCommand& command)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutControlCommand");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(command.Marshalling(data), AVSESSION_ERROR, "command Marshalling error");
    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(CONTROL_COMMAND_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetControlCommand(AVControlCommand& command)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(CONTROL_COMMAND_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);
    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");
    AVControlCommand *data = AVControlCommand::Unmarshalling(parcelData);
    CHECK_AND_RETURN_RET_LOG(data != nullptr, AVSESSION_ERROR, "Unmarshalling error");
    command = *data;
    delete data;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutCommonCommand");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteString(commonCommand), ERR_MARSHALLING, "Write commonCommand string failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&commandArgs), ERR_MARSHALLING, "Write commandArgs failed");

    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(COMMON_COMMAND_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
        "Put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetCommonCommand(std::string& commonCommand, AAFwk::WantParams& commandArgs)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(COMMON_COMMAND_KEY, dataVector) == AVSESSION_SUCCESS, AVSESSION_ERROR,
        "Get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "Get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "Alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);

    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "Parse parcel error");

    std::string commandString = parcelData.ReadString();
    commonCommand = std::string(commandString);
    AAFwk::WantParams *argsData = parcelData.ReadParcelable<AAFwk::WantParams>();
    if (argsData == nullptr) {
        SLOGE("GetCommonCommand: read parcelable commonCommand failed");
        delete argsData;
        return AVSESSION_ERROR;
    }
    commandArgs = AAFwk::WantParams(*argsData);
    delete argsData;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutSessionEvent");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteString(event), ERR_MARSHALLING, "write event string failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&args), ERR_MARSHALLING, "Write WantParams failed");

    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(SESSION_EVENT_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetSessionEvent(std::string& event, AAFwk::WantParams& args)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(SESSION_EVENT_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);

    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");
                             
    std::string eventData = parcelData.ReadString();
    event = std::string(eventData);
    AAFwk::WantParams *argsData = parcelData.ReadParcelable<AAFwk::WantParams>();
    if (argsData == nullptr) {
        SLOGE("GetSessionEvent: read parcelable sessionEvent failed");
        delete argsData;
        return AVSESSION_ERROR;
    }
    args = AAFwk::WantParams(*argsData);

    delete argsData;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutAVQueueItems(const std::vector<AVQueueItem>& items)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutAVQueueItems");
    Parcel data;
    
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(items.size()), AVSESSION_ERROR, "write items num int32 failed");
    for (auto &parcelable : items) {
        CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&parcelable), AVSESSION_ERROR, "Write items failed");
    }

    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(QUEUE_ITEMS_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(QUEUE_ITEMS_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);

    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");

    std::vector<AVQueueItem> items_;
    int32_t itemNum = parcelData.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(itemNum >= 0, AVSESSION_ERROR, "parse int32 itemNum failed");
    for (int32_t i = 0; i < itemNum; i++) {
        AVQueueItem *item = parcelData.ReadParcelable<AVQueueItem>();
        if (item == nullptr) {
            SLOGE("GetAVQueueItems: read parcelable AVQueueItem failed");
            delete item;
            return ERR_UNMARSHALLING;
        }
        items_.emplace_back(*item);
        delete item;
    }
    items = items_;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutAVQueueTitle(const std::string& title)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutAVQueueTitle");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteString(title), ERR_MARSHALLING, "write title string failed");

    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(QUEUE_TITLE_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetAVQueueTitle(std::string& title)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(QUEUE_TITLE_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);

    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
                             AVSESSION_ERROR, "parse parcel error");

    std::string titleDate = parcelData.ReadString();
    title = std::string(titleDate);
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::PutExtras(const AAFwk::WantParams& extras)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSyncerImpl::PutExtras");
    Parcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&extras), ERR_MARSHALLING, "Write extras failed");

    uint8_t *parcelData = reinterpret_cast<uint8_t*>(data.GetData());
    std::vector<uint8_t> dataVector(data.GetDataSize());
    std::copy(parcelData, parcelData + data.GetDataSize(), dataVector.begin());

    CHECK_AND_RETURN_RET_LOG(PutData(EXTRAS_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "put data error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::GetExtras(AAFwk::WantParams& extras)
{
    std::vector<uint8_t> dataVector;
    CHECK_AND_RETURN_RET_LOG(GetData(EXTRAS_KEY, dataVector) == AVSESSION_SUCCESS,
        AVSESSION_ERROR, "get data error");
    CHECK_AND_RETURN_RET_LOG(dataVector.size() <= RECEIVE_DATA_SIZE_MAX, AVSESSION_ERROR, "get data size over range");
    DefaultAllocator allocator;
    uint8_t *allocateData = reinterpret_cast<uint8_t*>(allocator.Alloc(dataVector.size()));
    CHECK_AND_RETURN_RET_LOG(allocateData != nullptr, AVSESSION_ERROR, "alloc data fail");
    std::copy(dataVector.begin(), dataVector.end(), allocateData);

    Parcel parcelData;
    CHECK_AND_RETURN_RET_LOG(parcelData.ParseFrom(reinterpret_cast<uintptr_t>(allocateData), dataVector.size()),
        AVSESSION_ERROR, "parse parcel error");
    AAFwk::WantParams *extrasData = parcelData.ReadParcelable<AAFwk::WantParams>();
    if (extrasData == nullptr) {
        SLOGE("GetSessionEvent: read parcelable sessionEvent failed");
        delete extrasData;
        return AVSESSION_ERROR;
    }
    extras = AAFwk::WantParams(*extrasData);

    delete extrasData;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::RegisterDataNotifier(const ObjectDataNotifier& notifier)
{
    CHECK_AND_RETURN_RET_LOG(objectStore_ != nullptr && object_ != nullptr, AVSESSION_ERROR,
                             "objectStore_ or object_ is nullptr");
    objectDataNotifier_ = notifier;
    objectStore_->Watch(object_, shared_from_this());
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSyncerImpl::RegisterDisconnectNotifier(const ObjectDisconnectNotifier& notifier)
{
    CHECK_AND_RETURN_RET_LOG(objectStore_ != nullptr, AVSESSION_ERROR, "objectStore_ is nullptr");
    objectDisconnectNotifier_ = notifier;
    objectStore_->SetStatusNotifier(shared_from_this());
    return AVSESSION_SUCCESS;
}

void RemoteSessionSyncerImpl::Destroy()
{
    auto ret = objectStore_->UnWatch(object_);
    CHECK_AND_RETURN_LOG(ret == ObjectStore::SUCCESS, "UnWatch error");
    ret = objectStore_->DeleteObject(objectName_);
    CHECK_AND_RETURN_LOG(ret == ObjectStore::SUCCESS, "DeleteObject error");
    SLOGI("Destroy");
}

RemoteSessionSyncerImpl::~RemoteSessionSyncerImpl()
{
    SLOGI("RemoteSessionSyncerImpl");
}
} // namespace OHOS::AVSession