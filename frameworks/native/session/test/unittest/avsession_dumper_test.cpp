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

#include <gtest/gtest.h>

#include "avsession_dumper.h"

using namespace testing::ext;

namespace OHOS {
namespace AVSession {
class AVSessionDumperTest : public testing::Test {
public:
    std::unique_ptr<AVSessionService> avSessionService_ = nullptr;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AVSessionDumperTest::SetUpTestCase()
{}

void AVSessionDumperTest::TearDownTestCase()
{}

void AVSessionDumperTest::SetUp()
{
    avSessionService_ = std::make_unique<AVSessionService>(1, true);
}

void AVSessionDumperTest::TearDown()
{}

/**
* @tc.name: ShowHelp001
* @tc.desc: Test whether the string returned by showHelp is correct
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowHelp001, TestSize.Level1)
{
    SLOGI("ShowHelp001 begin");
    std::string argsHelp = "-h";
    std::string expectedString;
    std::string actualString;
    expectedString.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-show_metadata               :show all avsession metadata in the system\n")
        .append("-show_session_info           :show information of all sessions\n")
        .append("-show_controller_info        :show information of all controllers \n")
        .append("-show_error_info             :show error information about avsession\n")
        .append("-show_trusted_devices_Info   :show trusted devices Info\n");
    std::vector<std::string> args;
    args.push_back(argsHelp);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, expectedString);
    SLOGI("ShowHelp001 end");
}

/**
* @tc.name: ShowTrustedDevicesInfo001
* @tc.desc: Test whether the string returned by ShowTrustedDevicesInfo is correct
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowTrustedDevicesInfo001, TestSize.Level1)
{
    SLOGI("ShowTrustedDevicesInfo001 begin");
    std::string trustedDeviceInfo = "-show_trusted_devices_Info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(trustedDeviceInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowTrustedDevicesInfo001 end");
}

/**
* @tc.name: ShowSessionInfo001
* @tc.desc: Test whether the string returned by ShowSessionInfo is correct
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowSessionInfo001, TestSize.Level1)
{
    SLOGI("ShowSessionInfo001 begin");
    std::string showSessionInfo = "-show_session_info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(showSessionInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowSessionInfo001 end");
}

/**
* @tc.name: ShowControllerInfo001
* @tc.desc: Test whether the string returned by ShowControllerInfo is correct
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowControllerInfo, TestSize.Level1)
{
    SLOGI("ShowControllerInfo begin");
    std::string showControllerInfo = "-show_controller_info";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(showControllerInfo);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString.size() > 0, true);
    SLOGI("ShowControllerInfo end");
}

/**
* @tc.name: ShowErrorInfo001
* @tc.desc: Test whether errorInfo can be obtained
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowErrorInfo001, TestSize.Level1)
{
    SLOGI("ShowErrorInfo001 begin");
    std::string showErrorInfo = "-show_error_info";
    std::string inputString = "This is error info";
    std::string outputString;
    AVSessionDumper dumper;
    dumper.SetErrorInfo(inputString);
    std::vector<std::string> args;
    args.push_back(showErrorInfo);
    dumper.Dump(args, outputString, *avSessionService_);
    EXPECT_EQ(outputString.size() > inputString.size(), true);
    SLOGI("ShowErrorInfo001 end");
}

/**
* @tc.name: ShowIllegalInfo001
* @tc.desc: Show illegal info
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, ShowIllegalInfo001, TestSize.Level1)
{
    SLOGI("ShowIllegalInfo001 begin");
    std::string illegalInformation = "AVSession service, enter '-h' for usage.\n";
    std::string illegalArg = "illegalArg";
    std::string actualString;
    std::vector<std::string> args;
    args.push_back(illegalArg);
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, illegalInformation);
    SLOGI("ShowIllegalInfo001 end");
}

/**
* @tc.name: Dump001
* @tc.desc: Test dump function in unexpected situations
* @tc.type: FUNC
* @tc.require: I6RW8M
*/
HWTEST_F(AVSessionDumperTest, Dump001, TestSize.Level1)
{
    SLOGI("Dump001 begin");
    std::string illegalInformation = "AVSession service, enter '-h' for usage.\n";
    std::string actualString;
    std::vector<std::string> args;
    AVSessionDumper dumper;
    dumper.Dump(args, actualString, *avSessionService_);
    EXPECT_EQ(actualString, illegalInformation);
    SLOGI("Dump001 end");
}
} // namespace AVSession
} // namespace OHOS
