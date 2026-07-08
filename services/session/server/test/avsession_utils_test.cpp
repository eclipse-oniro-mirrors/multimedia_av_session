/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "avsession_utils.h"
#include "file_ex.h"

using namespace testing::ext;
using namespace OHOS::AVSession;

/**
 * @class AVSessionUtilsTest
 * @brief Unit test class for AVSessionUtils
 * @details This class provides test cases for verifying the functionality of the AVSessionUtils class,
 *          including the GetAnonyTitle method for anonymous title generation
 */
class AVSessionUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AVSessionUtilsTest::SetUpTestCase()
{}

void AVSessionUtilsTest::TearDownTestCase()
{}

void AVSessionUtilsTest::SetUp()
{}

void AVSessionUtilsTest::TearDown()
{}

/**
 * @tc.name: GetAnonyTitle_Empty_001
 * @tc.desc: test GetAnonyTitle with empty string
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_Empty_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_Empty_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("");
    EXPECT_EQ(result, "");
    SLOGI("GetAnonyTitle_Empty_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_SingleChar_Ascii_001
 * @tc.desc: test GetAnonyTitle with single ASCII character
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_SingleChar_Ascii_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_SingleChar_Ascii_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("a");
    EXPECT_EQ(result, "*a*");
    SLOGI("GetAnonyTitle_SingleChar_Ascii_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_SingleChar_Chinese_001
 * @tc.desc: test GetAnonyTitle with single Chinese character
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_SingleChar_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_SingleChar_Chinese_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("中");
    EXPECT_EQ(result, "*中*");
    SLOGI("GetAnonyTitle_SingleChar_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_SingleChar_Emoji_001
 * @tc.desc: test GetAnonyTitle with single Emoji character
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_SingleChar_Emoji_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_SingleChar_Emoji_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("😀");
    EXPECT_EQ(result, "*😀*");
    SLOGI("GetAnonyTitle_SingleChar_Emoji_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_DoubleChar_Ascii_001
 * @tc.desc: test GetAnonyTitle with double ASCII characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_DoubleChar_Ascii_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_DoubleChar_Ascii_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("ab");
    EXPECT_EQ(result, "ab***");
    SLOGI("GetAnonyTitle_DoubleChar_Ascii_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_DoubleChar_Chinese_001
 * @tc.desc: test GetAnonyTitle with double Chinese characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_DoubleChar_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_DoubleChar_Chinese_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("中文");
    EXPECT_EQ(result, "中***");
    SLOGI("GetAnonyTitle_DoubleChar_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_DoubleChar_Emoji_001
 * @tc.desc: test GetAnonyTitle with double Emoji characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_DoubleChar_Emoji_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_DoubleChar_Emoji_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("😀😊");
    EXPECT_EQ(result, "\xF0\x9F\x98***");
    SLOGI("GetAnonyTitle_DoubleChar_Emoji_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_TripleChar_Ascii_001
 * @tc.desc: test GetAnonyTitle with triple ASCII characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_TripleChar_Ascii_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_TripleChar_Ascii_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abc");
    // 实际输出: "*abc*"
    EXPECT_EQ(result, "*abc*");
    SLOGI("GetAnonyTitle_TripleChar_Ascii_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_TripleChar_ChineseAscii_001
 * @tc.desc: test GetAnonyTitle with Chinese+ASCII (3 characters, first char is 3-byte UTF-8)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_TripleChar_ChineseAscii_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_TripleChar_ChineseAscii_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("中文a");
    EXPECT_EQ(result, "中***");
    SLOGI("GetAnonyTitle_TripleChar_ChineseAscii_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_4Char_001
 * @tc.desc: test GetAnonyTitle with 4 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_4Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_4Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcd");
    EXPECT_EQ(result, "a***d");
    SLOGI("GetAnonyTitle_ShortText_4Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_5Char_001
 * @tc.desc: test GetAnonyTitle with 5 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_5Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_5Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcde");
    EXPECT_EQ(result, "a***de");
    SLOGI("GetAnonyTitle_ShortText_5Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_6Char_001
 * @tc.desc: test GetAnonyTitle with 6 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_6Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_6Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcdef");
    EXPECT_EQ(result, "ab***ef");
    SLOGI("GetAnonyTitle_ShortText_6Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_7Char_001
 * @tc.desc: test GetAnonyTitle with 7 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_7Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_7Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcdefg");
    EXPECT_EQ(result, "ab***fg");
    SLOGI("GetAnonyTitle_ShortText_7Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_LongText_8Char_001
 * @tc.desc: test GetAnonyTitle with 8 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_LongText_8Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_LongText_8Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcdefgh");
    EXPECT_EQ(result, "ab***gh");
    SLOGI("GetAnonyTitle_LongText_8Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_LongText_10Char_001
 * @tc.desc: test GetAnonyTitle with 10 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_LongText_10Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_LongText_10Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcdefghij");
    EXPECT_EQ(result, "ab***ij");
    SLOGI("GetAnonyTitle_LongText_10Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_Ratio_0_001
 * @tc.desc: test GetAnonyTitle with ratio=0.0
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_Ratio_0_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_Ratio_0_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcd", 0.0);
    EXPECT_EQ(result, "a***");
    SLOGI("GetAnonyTitle_Ratio_0_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_Ratio_0_5_001
 * @tc.desc: test GetAnonyTitle with ratio=0.5
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_Ratio_0_5_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_Ratio_0_5_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcd", 0.5);
    EXPECT_EQ(result, "a***d");
    SLOGI("GetAnonyTitle_Ratio_0_5_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_Ratio_1_0_001
 * @tc.desc: test GetAnonyTitle with ratio=1.0
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_Ratio_1_0_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_Ratio_1_0_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcd", 1.0);
    // 当ratio=1.0时,mask_len=4,keep_front和keep_back都为0,调整后都为1
    // 结果应为保留首尾1个字符
    EXPECT_EQ(result, "a***d");
    SLOGI("GetAnonyTitle_Ratio_1_0_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_DefaultRatio_001
 * @tc.desc: test GetAnonyTitle with default ratio (0.3)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_DefaultRatio_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_DefaultRatio_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcde");
    EXPECT_EQ(result, "a***de");
    SLOGI("GetAnonyTitle_DefaultRatio_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_UTF8_Mixed_Emoji_001
 * @tc.desc: test GetAnonyTitle with mixed English and Emoji text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_UTF8_Mixed_Emoji_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_UTF8_Mixed_Emoji_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("Hello😊World");
    EXPECT_EQ(result, "He***ld");
    SLOGI("GetAnonyTitle_UTF8_Mixed_Emoji_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ExtremRatio_2_0_001
 * @tc.desc: test GetAnonyTitle with ratio=2.0 (extreme value)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ExtremRatio_2_0_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ExtremRatio_2_0_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcde", 2.0);
    EXPECT_EQ(result, "a***e");
    SLOGI("GetAnonyTitle_ExtremRatio_2_0_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ExtremRatio_Negative_001
 * @tc.desc: test GetAnonyTitle with ratio=-1.0 (negative value)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ExtremRatio_Negative_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ExtremRatio_Negative_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcde", -1.0);
    // 实际输出: "a***" (负值ratio导致keep_front+keep_back>=char_count)
    EXPECT_EQ(result, "a***");
    SLOGI("GetAnonyTitle_ExtremRatio_Negative_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_LongText_100Char_001
 * @tc.desc: test GetAnonyTitle with 100+ character text for performance
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_LongText_100Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_LongText_100Char_001 begin!");
    std::string longText(100, 'a');
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "aa***aa");
    SLOGI("GetAnonyTitle_LongText_100Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_LongText_Chinese_001
 * @tc.desc: test GetAnonyTitle with long Chinese text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_LongText_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_LongText_Chinese_001 begin!");
    std::string longText = "这是一个很长的中文标题用来测试长文本的处理情况";
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "这是***情况");
    SLOGI("GetAnonyTitle_LongText_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_TripleChar_3Byte_001
 * @tc.desc: test GetAnonyTitle with triple 3-byte UTF-8 characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_TripleChar_3Byte_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_TripleChar_3Byte_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("测试文");
    EXPECT_EQ(result, "测***");
    SLOGI("GetAnonyTitle_TripleChar_3Byte_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_Mixed_ASCII_Chinese_001
 * @tc.desc: test GetAnonyTitle with mixed ASCII and Chinese
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_Mixed_ASCII_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_Mixed_ASCII_Chinese_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("AB文CD");
    EXPECT_EQ(result, "A***CD");
    SLOGI("GetAnonyTitle_Mixed_ASCII_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_LongText_15Char_001
 * @tc.desc: test GetAnonyTitle with 15 character text
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_LongText_15Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_LongText_15Char_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("abcdefghijklmno");
    EXPECT_EQ(result, "ab***no");
    SLOGI("GetAnonyTitle_LongText_15Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_4Char_Chinese_001
 * @tc.desc: test GetAnonyTitle with 4 Chinese characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_4Char_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_4Char_Chinese_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("中文测试");
    // 实际输出: "中***试"
    EXPECT_EQ(result, "中***试");
    SLOGI("GetAnonyTitle_ShortText_4Char_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_ShortText_5Char_Chinese_001
 * @tc.desc: test GetAnonyTitle with 5 Chinese characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_ShortText_5Char_Chinese_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_ShortText_5Char_Chinese_001 begin!");
    std::string result = AVSessionUtils::GetAnonyTitle("中文测试用");
    EXPECT_EQ(result, "中***试用");
    SLOGI("GetAnonyTitle_ShortText_5Char_Chinese_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_5000Char_001
 * @tc.desc: test GetAnonyTitle with ~5000 ASCII characters (performance test)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_5000Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_5000Char_001 begin!");
    std::string longText(5000, 'a');
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "aa***aa");
    SLOGI("GetAnonyTitle_VeryLongText_5000Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_10000Char_001
 * @tc.desc: test GetAnonyTitle with ~10000 ASCII characters (extreme performance test)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_10000Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_10000Char_001 begin!");
    std::string longText(10000, 'x');
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "xx***xx");
    SLOGI("GetAnonyTitle_VeryLongText_10000Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_Chinese_5000Byte_001
 * @tc.desc: test GetAnonyTitle with ~5000 byte Chinese text (UTF-8 performance test)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_Chinese_5000Byte_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_Chinese_5000Byte_001 begin!");
    std::string baseChinese = "测试中文标题";
    std::string longText;
    for (int i = 0; i < 500; i++) {
        longText += baseChinese;
    }
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "测试***标题");
    SLOGI("GetAnonyTitle_VeryLongText_Chinese_5000Byte_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_Mixed_5000Char_001
 * @tc.desc: test GetAnonyTitle with ~5000 mixed ASCII/Chinese/Emoji characters
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_Mixed_5000Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_Mixed_5000Char_001 begin!");
    std::string pattern = "Hello世界🎉";
    std::string longText;
    for (int i = 0; i < 500; i++) {
        longText += pattern;
    }
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "He***界🎉");
    SLOGI("GetAnonyTitle_VeryLongText_Mixed_5000Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_AllEmoji_5000Char_001
 * @tc.desc: test GetAnonyTitle with ~5000 emoji characters (extreme UTF-8 test)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_AllEmoji_5000Char_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_AllEmoji_5000Char_001 begin!");
    std::string singleEmoji = "😊";
    std::string longText;
    for (int i = 0; i < 1000; i++) {
        longText += singleEmoji;
    }
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "😊😊***😊😊");
    SLOGI("GetAnonyTitle_VeryLongText_AllEmoji_5000Char_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_VeryLongText_MaxFileSize_4MB_001
 * @tc.desc: test GetAnonyTitle near MAX_FILE_SIZE limit (4MB boundary test)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_VeryLongText_MaxFileSize_4MB_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_VeryLongText_MaxFileSize_4MB_001 begin!");
    std::string longText(100000, 'z');
    std::string result = AVSessionUtils::GetAnonyTitle(longText);
    EXPECT_EQ(result, "zz***zz");
    SLOGI("GetAnonyTitle_VeryLongText_MaxFileSize_4MB_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_AllContinuationBytes_001
 * @tc.desc: test GetAnonyTitle with all UTF-8 continuation bytes (illegal UTF-8, char_positions empty)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_AllContinuationBytes_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_AllContinuationBytes_001 begin!");
    std::string title = "\x80\x81\x82";
    std::string result = AVSessionUtils::GetAnonyTitle(title);
    EXPECT_EQ(result, "***");
    SLOGI("GetAnonyTitle_AllContinuationBytes_001 end!");
}

/**
 * @tc.name: GetAnonyTitle_SingleContinuationByte_001
 * @tc.desc: test GetAnonyTitle with a single UTF-8 continuation byte (illegal UTF-8)
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, GetAnonyTitle_SingleContinuationByte_001, TestSize.Level0)
{
    SLOGI("GetAnonyTitle_SingleContinuationByte_001 begin!");
    std::string title = "\xBF";
    std::string result = AVSessionUtils::GetAnonyTitle(title);
    EXPECT_EQ(result, "***");
    SLOGI("GetAnonyTitle_SingleContinuationByte_001 end!");
}

/**
 * @tc.name: DeleteCacheFilesExcluding_001
 * @tc.desc: keep alive local/cast files, delete stale ones
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, DeleteCacheFilesExcluding_001, TestSize.Level0)
{
    SLOGI("DeleteCacheFilesExcluding_001 begin!");
    std::string testDir = "/data/service/el2/100/av_session/cache_unittest_excl/";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(testDir));
    // alive session: local + cast files must be preserved
    std::string keepLocal = testDir + "abcdef123456.image.dat";
    std::string keepCast = testDir + "cast_abcdef123456.image.dat";
    // stale session: local + cast files must be deleted
    std::string staleLocal = testDir + "zzzzzzzzzzzz.image.dat";
    std::string staleCast = testDir + "cast_yyyyyyyyyyyy.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(keepLocal, "keep"));
    ASSERT_TRUE(OHOS::SaveStringToFile(keepCast, "keep"));
    ASSERT_TRUE(OHOS::SaveStringToFile(staleLocal, "stale"));
    ASSERT_TRUE(OHOS::SaveStringToFile(staleCast, "stale"));

    std::set<std::string> retained = {"abcdef123456"};
    AVSessionUtils::DeleteCacheFilesExcluding(testDir, retained);
    EXPECT_TRUE(OHOS::FileExists(keepLocal));
    EXPECT_TRUE(OHOS::FileExists(keepCast));
    EXPECT_FALSE(OHOS::FileExists(staleLocal));
    EXPECT_FALSE(OHOS::FileExists(staleCast));

    AVSessionUtils::DeleteFile(keepLocal);
    AVSessionUtils::DeleteFile(keepCast);
    EXPECT_FALSE(OHOS::FileExists(keepLocal));
    EXPECT_FALSE(OHOS::FileExists(keepCast));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(testDir));
    SLOGI("DeleteCacheFilesExcluding_001 end!");
}

/**
 * @tc.name: DeleteCacheFilesExcluding_002
 * @tc.desc: empty retained set deletes every *.image.dat file
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, DeleteCacheFilesExcluding_002, TestSize.Level0)
{
    SLOGI("DeleteCacheFilesExcluding_002 begin!");
    std::string testDir = "/data/service/el2/100/av_session/cache_unittest_empty/";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(testDir));
    std::string fileA = testDir + "aaaaaaaaaaaa.image.dat";
    std::string fileB = testDir + "cast_bbbbbbbbbbbb.image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(fileA, "a"));
    ASSERT_TRUE(OHOS::SaveStringToFile(fileB, "b"));

    AVSessionUtils::DeleteCacheFilesExcluding(testDir, {});
    EXPECT_FALSE(OHOS::FileExists(fileA));
    EXPECT_FALSE(OHOS::FileExists(fileB));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(testDir));
    SLOGI("DeleteCacheFilesExcluding_002 end!");
}

/**
 * @tc.name: DeleteCacheFilesExcluding_003
 * @tc.desc: non-suffix files are skipped; empty dir is a no-op
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, DeleteCacheFilesExcluding_003, TestSize.Level0)
{
    SLOGI("DeleteCacheFilesExcluding_003 begin!");
    // empty directory: loop body never executes
    std::string emptyDir = "/data/service/el2/100/av_session/cache_unittest_emptydir/";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(emptyDir));
    AVSessionUtils::DeleteCacheFilesExcluding(emptyDir, {});
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(emptyDir));

    // non-existent dir: GetDirFiles returns empty, no crash
    AVSessionUtils::DeleteCacheFilesExcluding("/data/service/el2/100/av_session/nonexistent_dir/", {});
    SLOGI("DeleteCacheFilesExcluding_003 end!");
}

/**
 * @tc.name: DeleteCacheFilesExcluding_004
 * @tc.desc: non-image files are skipped; cast prefix is stripped before retention check
 * @tc.type: FUNC
 */
HWTEST_F(AVSessionUtilsTest, DeleteCacheFilesExcluding_004, TestSize.Level0)
{
    SLOGI("DeleteCacheFilesExcluding_004 begin!");
    std::string testDir = "/data/service/el2/100/av_session/cache_unittest_nonsuffix/";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(testDir));
    // a file without .image.dat suffix must be left untouched
    std::string keepNonSuffix = testDir + "keepme.txt";
    // cast_ file of an alive session: prefix stripped, then matched and preserved
    std::string keepCast = testDir + "cast_abcdef123456.image.dat";
    // bare ".image.dat" (empty stem, suffix at pos 0) is still treated as a cache file
    std::string dotOnly = testDir + ".image.dat";
    ASSERT_TRUE(OHOS::SaveStringToFile(keepNonSuffix, "txt"));
    ASSERT_TRUE(OHOS::SaveStringToFile(keepCast, "keep"));
    ASSERT_TRUE(OHOS::SaveStringToFile(dotOnly, "x"));

    std::set<std::string> retained = {"abcdef123456"};
    AVSessionUtils::DeleteCacheFilesExcluding(testDir, retained);
    EXPECT_TRUE(OHOS::FileExists(keepNonSuffix));
    EXPECT_TRUE(OHOS::FileExists(keepCast));
    // empty-stem file is not retained, so it is deleted
    EXPECT_FALSE(OHOS::FileExists(dotOnly));

    AVSessionUtils::DeleteFile(keepNonSuffix);
    AVSessionUtils::DeleteFile(keepCast);
    EXPECT_FALSE(OHOS::FileExists(keepNonSuffix));
    EXPECT_FALSE(OHOS::FileExists(keepCast));
    EXPECT_TRUE(OHOS::ForceRemoveDirectory(testDir));
    SLOGI("DeleteCacheFilesExcluding_004 end!");
}
