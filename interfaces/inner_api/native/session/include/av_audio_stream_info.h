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
 
#ifndef AV_AUDIO_STREAM_INFO_H
#define AV_AUDIO_STREAM_INFO_H

namespace OHOS::AVSession {

const uint32_t CH_MODE_OFFSET = 44;
const uint32_t CH_HOA_ORDNUM_OFFSET = 0;
const uint32_t CH_HOA_COMORD_OFFSET = 8;
const uint32_t CH_HOA_NOR_OFFSET = 12;

// sampling rate
enum AudioSamplingRate {
    SAMPLE_RATE_8000 = 8000,
    SAMPLE_RATE_11025 = 11025,
    SAMPLE_RATE_12000 = 12000,
    SAMPLE_RATE_16000 = 16000,
    SAMPLE_RATE_22050 = 22050,
    SAMPLE_RATE_24000 = 24000,
    SAMPLE_RATE_32000 = 32000,
    SAMPLE_RATE_44100 = 44100,
    SAMPLE_RATE_48000 = 48000,
    SAMPLE_RATE_64000 = 64000,
    SAMPLE_RATE_88200 = 88200,
    SAMPLE_RATE_96000 = 96000,
    SAMPLE_RATE_176400 = 176400,
    SAMPLE_RATE_192000 = 192000
};

enum AudioEncodingType {
    ENCODING_INVALID = -1,
    ENCODING_PCM = 0,
    ENCODING_AUDIOVIVID = 1
};


// format
enum AudioSampleFormat : uint8_t {
    SAMPLE_U8 = 0,
    SAMPLE_S16LE = 1,
    SAMPLE_S24LE = 2,
    SAMPLE_S32LE = 3,
    SAMPLE_F32LE = 4,
    INVALID_WIDTH = -1
};

// channel
enum AudioChannel : uint8_t {
    CHANNEL_UNKNOW = 0,
    MONO = 1,
    STEREO = 2,
    CHANNEL_3 = 3,
    CHANNEL_4 = 4,
    CHANNEL_5 = 5,
    CHANNEL_6 = 6,
    CHANNEL_7 = 7,
    CHANNEL_8 = 8,
    CHANNEL_9 = 9,
    CHANNEL_10 = 10,
    CHANNEL_11 = 11,
    CHANNEL_12 = 12,
    CHANNEL_13 = 13,
    CHANNEL_14 = 14,
    CHANNEL_15 = 15,
    CHANNEL_16 = 16
};

enum AudioChannelSet: uint64_t {
    FRONT_LEFT = 1ULL << 0U, FRONT_RIGHT = 1ULL << 1U, FRONT_CENTER = 1ULL << 2U,
    LOW_FREQUENCY = 1ULL << 3U,
    BACK_LEFT = 1ULL << 4U, BACK_RIGHT = 1ULL << 5U,
    FRONT_LEFT_OF_CENTER = 1ULL << 6U, FRONT_RIGHT_OF_CENTER = 1ULL << 7U,
    BACK_CENTER = 1ULL << 8U,
    SIDE_LEFT = 1ULL << 9U, SIDE_RIGHT = 1ULL << 10U,
    TOP_CENTER = 1ULL << 11U,
    TOP_FRONT_LEFT = 1ULL << 12U, TOP_FRONT_CENTER = 1ULL << 13U, TOP_FRONT_RIGHT = 1ULL << 14U,
    TOP_BACK_LEFT = 1ULL << 15U, TOP_BACK_CENTER = 1ULL << 16U, TOP_BACK_RIGHT = 1ULL << 17U,
    STEREO_LEFT = 1ULL << 29U, STEREO_RIGHT = 1ULL << 30U,
    WIDE_LEFT = 1ULL << 31U, WIDE_RIGHT = 1ULL << 32U,
    SURROUND_DIRECT_LEFT = 1ULL << 33U, SURROUND_DIRECT_RIGHT = 1ULL << 34U,
    LOW_FREQUENCY_2 = 1ULL << 35U,
    TOP_SIDE_LEFT = 1ULL << 36U, TOP_SIDE_RIGHT = 1ULL << 37U,
    BOTTOM_FRONT_CENTER = 1ULL << 38U, BOTTOM_FRONT_LEFT = 1ULL << 39U, BOTTOM_FRONT_RIGHT = 1ULL << 40U
};

enum ChannelMode: uint64_t {
    CHANNEL_MDOE_NORMAL = 0ULL,
    CHANNEL_MDOE_AMBISONIC = 1ULL,
    CHANNEL_MDOE_BINAURAL = 2ULL
};

enum HOAOrderNumber: uint64_t {
    HOA_ORDNUM_1 = 1ULL,
    HOA_ORDNUM_2 = 2ULL,
    HOA_ORDNUM_3 = 3ULL
};

enum HOAComponentOrdering: uint64_t {
    HOA_COMORD_ACN = 0ULL,
    HOA_COMORD_FUMA = 1ULL,
};

enum HOANormalization: uint64_t {
    HOA_NOR_N3D = 0ULL,
    HOA_NOR_SN3D = 1ULL,
};

enum AudioChannelLayout: uint64_t {
    CH_LAYOUT_UNKNOWN = 0ULL,
    /** Channel count: 1*/
    CH_LAYOUT_MONO = FRONT_CENTER,
    /** Channel count: 2*/
    CH_LAYOUT_STEREO = FRONT_LEFT | FRONT_RIGHT,
    CH_LAYOUT_STEREO_DOWNMIX = STEREO_LEFT | STEREO_RIGHT,
    /** Channel count: 3*/
    CH_LAYOUT_2POINT1 = CH_LAYOUT_STEREO | LOW_FREQUENCY,
    CH_LAYOUT_3POINT0 = CH_LAYOUT_STEREO | BACK_CENTER,
    CH_LAYOUT_SURROUND = CH_LAYOUT_STEREO | FRONT_CENTER,
    /** Channel count: 4*/
    CH_LAYOUT_3POINT1 = CH_LAYOUT_SURROUND | LOW_FREQUENCY,
    CH_LAYOUT_4POINT0 = CH_LAYOUT_SURROUND | BACK_CENTER,
    CH_LAYOUT_QUAD_SIDE = CH_LAYOUT_STEREO | SIDE_LEFT | SIDE_RIGHT,
    CH_LAYOUT_QUAD = CH_LAYOUT_STEREO | BACK_LEFT | BACK_RIGHT,
    CH_LAYOUT_2POINT0POINT2 = CH_LAYOUT_STEREO | TOP_SIDE_LEFT | TOP_SIDE_RIGHT,
    /** Channel count: 5*/
    CH_LAYOUT_4POINT1 = CH_LAYOUT_4POINT0 | LOW_FREQUENCY,
    CH_LAYOUT_5POINT0 = CH_LAYOUT_SURROUND | SIDE_LEFT | SIDE_RIGHT,
    CH_LAYOUT_5POINT0_BACK = CH_LAYOUT_SURROUND | BACK_LEFT | BACK_RIGHT,
    CH_LAYOUT_2POINT1POINT2 = CH_LAYOUT_2POINT0POINT2 | LOW_FREQUENCY,
    CH_LAYOUT_3POINT0POINT2 = CH_LAYOUT_2POINT0POINT2 | FRONT_CENTER,
    /** Channel count: 6*/
    CH_LAYOUT_5POINT1 = CH_LAYOUT_5POINT0 | LOW_FREQUENCY,
    CH_LAYOUT_5POINT1_BACK = CH_LAYOUT_5POINT0_BACK | LOW_FREQUENCY,
    CH_LAYOUT_6POINT0 = CH_LAYOUT_5POINT0 | BACK_CENTER,
    CH_LAYOUT_HEXAGONAL = CH_LAYOUT_5POINT0_BACK | BACK_CENTER,
    CH_LAYOUT_3POINT1POINT2 = CH_LAYOUT_3POINT1 | TOP_FRONT_LEFT | TOP_FRONT_RIGHT,
    CH_LAYOUT_6POINT0_FRONT = CH_LAYOUT_QUAD_SIDE | FRONT_LEFT_OF_CENTER | FRONT_RIGHT_OF_CENTER,
    /** Channel count: 7*/
    CH_LAYOUT_6POINT1 = CH_LAYOUT_5POINT1 | BACK_CENTER,
    CH_LAYOUT_6POINT1_BACK = CH_LAYOUT_5POINT1_BACK | BACK_CENTER,
    CH_LAYOUT_6POINT1_FRONT = CH_LAYOUT_6POINT0_FRONT | LOW_FREQUENCY,
    CH_LAYOUT_7POINT0 = CH_LAYOUT_5POINT0 | BACK_LEFT | BACK_RIGHT,
    CH_LAYOUT_7POINT0_FRONT = CH_LAYOUT_5POINT0 | FRONT_LEFT_OF_CENTER | FRONT_RIGHT_OF_CENTER,
    /** Channel count: 8*/
    CH_LAYOUT_7POINT1 = CH_LAYOUT_5POINT1 | BACK_LEFT | BACK_RIGHT,
    CH_LAYOUT_OCTAGONAL = CH_LAYOUT_5POINT0 | BACK_CENTER | BACK_LEFT | BACK_RIGHT,
    CH_LAYOUT_5POINT1POINT2 = CH_LAYOUT_5POINT1 | TOP_SIDE_LEFT | TOP_SIDE_RIGHT,
    CH_LAYOUT_7POINT1_WIDE = CH_LAYOUT_5POINT1 | FRONT_LEFT_OF_CENTER | FRONT_RIGHT_OF_CENTER,
    CH_LAYOUT_7POINT1_WIDE_BACK = CH_LAYOUT_5POINT1_BACK | FRONT_LEFT_OF_CENTER | FRONT_RIGHT_OF_CENTER,
    /** Channel count: 10*/
    CH_LAYOUT_5POINT1POINT4 = CH_LAYOUT_5POINT1 | TOP_FRONT_LEFT | TOP_FRONT_RIGHT | TOP_BACK_LEFT |TOP_BACK_RIGHT,
    CH_LAYOUT_7POINT1POINT2 = CH_LAYOUT_7POINT1 | TOP_SIDE_LEFT | TOP_SIDE_RIGHT,
    /** Channel count: 12*/
    CH_LAYOUT_7POINT1POINT4 = CH_LAYOUT_7POINT1 | TOP_FRONT_LEFT | TOP_FRONT_RIGHT | TOP_BACK_LEFT | TOP_BACK_RIGHT,
    CH_LAYOUT_10POINT2 = FRONT_LEFT | FRONT_RIGHT | FRONT_CENTER | TOP_FRONT_LEFT | TOP_FRONT_RIGHT | BACK_LEFT
        | BACK_RIGHT | BACK_CENTER | SIDE_LEFT | SIDE_RIGHT | WIDE_LEFT | WIDE_RIGHT,
    /** Channel count: 14*/
    CH_LAYOUT_9POINT1POINT4 = CH_LAYOUT_7POINT1POINT4 | WIDE_LEFT | WIDE_RIGHT,
    /** Channel count: 16*/
    CH_LAYOUT_9POINT1POINT6 = CH_LAYOUT_9POINT1POINT4 | TOP_SIDE_LEFT | TOP_SIDE_RIGHT,
    CH_LAYOUT_HEXADECAGONAL = CH_LAYOUT_OCTAGONAL | WIDE_LEFT | WIDE_RIGHT | TOP_BACK_LEFT | TOP_BACK_RIGHT
        | TOP_BACK_CENTER | TOP_FRONT_CENTER | TOP_FRONT_LEFT | TOP_FRONT_RIGHT,
    /** HOA: fitst order*/
    CH_LAYOUT_HOA_ORDER1_ACN_N3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_1 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_N3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER1_ACN_SN3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_1 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_SN3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER1_FUMA = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_1 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_FUMA << CH_HOA_COMORD_OFFSET),
    /** HOA: second order*/
    CH_LAYOUT_HOA_ORDER2_ACN_N3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_2 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_N3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER2_ACN_SN3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_2 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_SN3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER2_FUMA = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_2 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_FUMA << CH_HOA_COMORD_OFFSET),
    /** HOA: third order*/
    CH_LAYOUT_HOA_ORDER3_ACN_N3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_3 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_N3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER3_ACN_SN3D = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_3 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_ACN << CH_HOA_COMORD_OFFSET) | (HOA_NOR_SN3D << CH_HOA_NOR_OFFSET),
    CH_LAYOUT_HOA_ORDER3_FUMA = (CHANNEL_MDOE_AMBISONIC << CH_MODE_OFFSET) | (HOA_ORDNUM_3 << CH_HOA_ORDNUM_OFFSET)
        | (HOA_COMORD_FUMA << CH_HOA_COMORD_OFFSET),
};

class AudioStreamInfo {
public:
    AudioSamplingRate samplingRate;
    AudioEncodingType encoding = AudioEncodingType::ENCODING_PCM;
    AudioSampleFormat format = AudioSampleFormat::INVALID_WIDTH;
    AudioChannel channels;
    AudioChannelLayout channelLayout  = AudioChannelLayout::CH_LAYOUT_UNKNOWN;
    constexpr AudioStreamInfo(AudioSamplingRate samplingRate_, AudioEncodingType encoding_, AudioSampleFormat format_,
        AudioChannel channels_, AudioChannelLayout channelLayout_ = AudioChannelLayout::CH_LAYOUT_UNKNOWN)
        : samplingRate(samplingRate_), encoding(encoding_), format(format_), channels(channels_),
        channelLayout(channelLayout_)
    {}
    AudioStreamInfo() = default;
    bool WriteToParcel(Parcel &parcel) const
    {
        return parcel.WriteInt32(static_cast<int32_t>(samplingRate))
            && parcel.WriteInt32(static_cast<int32_t>(encoding))
            && parcel.WriteInt32(static_cast<int32_t>(format))
            && parcel.WriteInt32(static_cast<int32_t>(channels))
            && parcel.WriteUint64(channelLayout);
    }
    bool ReadFromParcel(Parcel &parcel)
    {
        samplingRate = static_cast<AudioSamplingRate>(parcel.ReadInt32());
        encoding = static_cast<AudioEncodingType>(parcel.ReadInt32());
        format = static_cast<AudioSampleFormat>(parcel.ReadInt32());
        channels = static_cast<AudioChannel>(parcel.ReadInt32());
        channelLayout = static_cast<AudioChannelLayout>(parcel.ReadUint64());
        return true;
    }
};

} // namespace OHOS::AVSession

#endif // AV_AUDIO_STREAM_INFO_H