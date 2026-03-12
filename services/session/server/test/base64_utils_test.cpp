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

#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "base64_utils.h"
#include "avsession_log.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

class Base64UtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Base64UtilsTest::SetUpTestCase()
{
    SLOGI("Base64UtilsTest SetUpTestCase");
}

void Base64UtilsTest::TearDownTestCase()
{
    SLOGI("Base64UtilsTest TearDownTestCase");
}

void Base64UtilsTest::SetUp()
{
    SLOGI("Base64UtilsTest SetUp");
}

void Base64UtilsTest::TearDown()
{
    SLOGI("Base64UtilsTest TearDown");
}

/**
 * @tc.name: Base64Encode001
 * @tc.desc: Test Base64Encode with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode001, TestSize.Level0)
{
    std::vector<uint8_t> data;
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "");
}

/**
 * @tc.name: Base64Encode002
 * @tc.desc: Test Base64Encode with single byte
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode002, TestSize.Level0)
{
    std::vector<uint8_t> data = {'A'};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "QQ==");
}

/**
 * @tc.name: Base64Encode003
 * @tc.desc: Test Base64Encode with two bytes
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode003, TestSize.Level0)
{
    std::vector<uint8_t> data = {'A', 'B'};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "QUI=");
}

/**
 * @tc.name: Base64Encode004
 * @tc.desc: Test Base64Encode with three bytes (no padding needed)
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode004, TestSize.Level0)
{
    std::vector<uint8_t> data = {'A', 'B', 'C'};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "QUJD");
}

/**
 * @tc.name: Base64Encode005
 * @tc.desc: Test Base64Encode with four bytes
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode005, TestSize.Level0)
{
    std::vector<uint8_t> data = {'A', 'B', 'C', 'D'};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "QUJDRA==");
}

/**
 * @tc.name: Base64Encode006
 * @tc.desc: Test Base64Encode with string "Hello"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode006, TestSize.Level0)
{
    std::string input = "Hello";
    std::vector<uint8_t> data(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "SGVsbG8=");
}

/**
 * @tc.name: Base64Encode007
 * @tc.desc: Test Base64Encode with string "Hello World"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode007, TestSize.Level0)
{
    std::string input = "Hello World";
    std::vector<uint8_t> data(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "SGVsbG8gV29ybGQ=");
}

/**
 * @tc.name: Base64Encode008
 * @tc.desc: Test Base64Encode with binary data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode008, TestSize.Level0)
{
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_FALSE(encoded.empty());
}

/**
 * @tc.name: Base64Encode009
 * @tc.desc: Test Base64Encode with all zero bytes
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode009, TestSize.Level0)
{
    std::vector<uint8_t> data = {0x00, 0x00, 0x00};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "AAAA");
}

/**
 * @tc.name: Base64Encode010
 * @tc.desc: Test Base64Encode with all 0xFF bytes
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Encode010, TestSize.Level0)
{
    std::vector<uint8_t> data = {0xFF, 0xFF, 0xFF};
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_EQ(encoded, "////");
}

/**
 * @tc.name: Base64Decode001
 * @tc.desc: Test Base64Decode with empty string
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode001, TestSize.Level0)
{
    std::string encoded = "";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_TRUE(decoded.empty());
}

/**
 * @tc.name: Base64Decode002
 * @tc.desc: Test Base64Decode with "QQ=="
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode002, TestSize.Level0)
{
    std::string encoded = "QQ==";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 1);
    EXPECT_EQ(decoded[0], 'A');
}

/**
 * @tc.name: Base64Decode003
 * @tc.desc: Test Base64Decode with "QUI="
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode003, TestSize.Level0)
{
    std::string encoded = "QUI=";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 2);
    EXPECT_EQ(decoded[0], 'A');
    EXPECT_EQ(decoded[1], 'B');
}

/**
 * @tc.name: Base64Decode004
 * @tc.desc: Test Base64Decode with "QUJD"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode004, TestSize.Level0)
{
    std::string encoded = "QUJD";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 3);
    EXPECT_EQ(decoded[0], 'A');
    EXPECT_EQ(decoded[1], 'B');
    EXPECT_EQ(decoded[2], 'C');
}

/**
 * @tc.name: Base64Decode005
 * @tc.desc: Test Base64Decode with "SGVsbG8="
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode005, TestSize.Level0)
{
    std::string encoded = "SGVsbG8=";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    std::string result(decoded.begin(), decoded.end());
    EXPECT_EQ(result, "Hello");
}

/**
 * @tc.name: Base64Decode006
 * @tc.desc: Test Base64Decode with "SGVsbG8gV29ybGQ="
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode006, TestSize.Level0)
{
    std::string encoded = "SGVsbG8gV29ybGQ=";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    std::string result(decoded.begin(), decoded.end());
    EXPECT_EQ(result, "Hello World");
}

/**
 * @tc.name: Base64Decode007
 * @tc.desc: Test Base64Decode with invalid characters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode007, TestSize.Level0)
{
    std::string encoded = "Q@JD"; // Invalid character '@'
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    // Should skip invalid characters
    EXPECT_FALSE(decoded.empty());
}

/**
 * @tc.name: Base64Decode008
 * @tc.desc: Test Base64Decode with "AAAA"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode008, TestSize.Level0)
{
    std::string encoded = "AAAA";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 3);
    EXPECT_EQ(decoded[0], 0x00);
    EXPECT_EQ(decoded[1], 0x00);
    EXPECT_EQ(decoded[2], 0x00);
}

/**
 * @tc.name: Base64Decode009
 * @tc.desc: Test Base64Decode with "////"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode009, TestSize.Level0)
{
    std::string encoded = "////";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 3);
    EXPECT_EQ(decoded[0], 0xFF);
    EXPECT_EQ(decoded[1], 0xFF);
    EXPECT_EQ(decoded[2], 0xFF);
}

/**
 * @tc.name: Base64Decode010
 * @tc.desc: Test Base64Decode without padding
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64Decode010, TestSize.Level0)
{
    std::string encoded = "SGVsbG8"; // No padding
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    std::string result(decoded.begin(), decoded.end());
    EXPECT_EQ(result, "Hello");
}

/**
 * @tc.name: Base64RoundTrip001
 * @tc.desc: Test encode-decode round trip with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip001, TestSize.Level0)
{
    std::vector<uint8_t> original;
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip002
 * @tc.desc: Test encode-decode round trip with "ABC"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip002, TestSize.Level0)
{
    std::string input = "ABC";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip003
 * @tc.desc: Test encode-decode round trip with "Hello World"
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip003, TestSize.Level0)
{
    std::string input = "Hello World";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip004
 * @tc.desc: Test encode-decode round trip with binary data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip004, TestSize.Level0)
{
    std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF};
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip005
 * @tc.desc: Test encode-decode round trip with longer string
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip005, TestSize.Level0)
{
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip006
 * @tc.desc: Test encode-decode round trip with numbers
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip006, TestSize.Level0)
{
    std::string input = "1234567890";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip007
 * @tc.desc: Test encode-decode round trip with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip007, TestSize.Level0)
{
    std::string input = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip008
 * @tc.desc: Test encode-decode round trip with newlines and spaces
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip008, TestSize.Level0)
{
    std::string input = "Line1\nLine2\nLine3";
    std::vector<uint8_t> original(input.begin(), input.end());
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip009
 * @tc.desc: Test encode-decode round trip with all byte values
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip009, TestSize.Level0)
{
    std::vector<uint8_t> original;
    for (int i = 0; i < 256; i++) {
        original.push_back(static_cast<uint8_t>(i));
    }
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64RoundTrip010
 * @tc.desc: Test encode-decode round trip with large data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64RoundTrip010, TestSize.Level0)
{
    std::vector<uint8_t> original;
    for (int i = 0; i < 1000; i++) {
        original.push_back(static_cast<uint8_t>(i % 256));
    }
    std::string encoded = Base64Utils::Base64Encode(original);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

/**
 * @tc.name: Base64EncodePerformance001
 * @tc.desc: Test Base64Encode performance with large data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EncodePerformance001, TestSize.Level1)
{
    std::vector<uint8_t> data(10000, 'A');
    std::string encoded = Base64Utils::Base64Encode(data);
    EXPECT_FALSE(encoded.empty());
    // Encoded size should be approximately 4/3 of original size
    EXPECT_GE(encoded.size(), data.size() * 4 / 3 - 2);
    EXPECT_LE(encoded.size(), data.size() * 4 / 3 + 3);
}

/**
 * @tc.name: Base64DecodePerformance001
 * @tc.desc: Test Base64Decode performance with large data
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64DecodePerformance001, TestSize.Level1)
{
    std::string encoded(10000, 'A');
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_FALSE(decoded.empty());
}

/**
 * @tc.name: Base64EdgeCases001
 * @tc.desc: Test Base64 with single padding character
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EdgeCases001, TestSize.Level0)
{
    std::string encoded = "QQ=";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_FALSE(decoded.empty());
}

/**
 * @tc.name: Base64EdgeCases002
 * @tc.desc: Test Base64 with mixed case
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EdgeCases002, TestSize.Level0)
{
    std::vector<uint8_t> data = {'a', 'B', 'c', 'D'};
    std::string encoded = Base64Utils::Base64Encode(data);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(data, decoded);
}

/**
 * @tc.name: Base64EdgeCases003
 * @tc.desc: Test Base64 with Unicode-like bytes
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EdgeCases003, TestSize.Level0)
{
    std::vector<uint8_t> data = {0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD}; // UTF-8 for "你好"
    std::string encoded = Base64Utils::Base64Encode(data);
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    EXPECT_EQ(data, decoded);
}

/**
 * @tc.name: Base64EdgeCases004
 * @tc.desc: Test Base64Decode with multiple padding characters
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EdgeCases004, TestSize.Level0)
{
    std::string encoded = "QQ==";
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    ASSERT_EQ(decoded.size(), 1);
    EXPECT_EQ(decoded[0], 'A');
}

/**
 * @tc.name: Base64EdgeCases005
 * @tc.desc: Test Base64 with whitespace in encoded string
 * @tc.type: FUNC
 * @tc.require:
 */
static HWTEST_F(Base64UtilsTest, Base64EdgeCases005, TestSize.Level0)
{
    std::string encoded = "QU JD"; // Contains space
    std::vector<uint8_t> decoded = Base64Utils::Base64Decode(encoded);
    // Should handle whitespace gracefully (skip it)
    EXPECT_FALSE(decoded.empty());
}
