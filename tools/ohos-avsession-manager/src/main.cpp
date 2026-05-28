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

#include "avsession_manager.h"
#include "avsession_controller.h"
#include "av_session.h"
#include "avsession_info.h"
#include "avsession_errors.h"
#include "avplayback_state.h"
#include "avcontrol_command.h"
#include "key_event.h"
#include "element_name.h"
#include "utils.h"
#include "nlohmann/json.hpp"
#include <cstring>
#include <cerrno>
#include <cmath>
#include <limits>
#include <cstdlib>
#include <unordered_map>
#include <functional>
#include <memory>

namespace OHOS::AVSession::Cli {

constexpr int32_t ERR_ARG_MISSING = -1001;
constexpr int32_t ERR_ARG_INVALID = -1002;

constexpr int JSON_DUMP_INDENT = 2;
constexpr int MIN_ARG_COUNT = 2;
constexpr int COMMAND_ARG_INDEX = 1;
constexpr int SUBCOMMAND_ARG_INDEX = 2;

constexpr int64_t DEFAULT_FORWARD_TIME = 15000;
constexpr int64_t DEFAULT_REWIND_TIME = 15000;
constexpr double DEFAULT_SPEED = 1.0;
constexpr int32_t DEFAULT_LOOP_MODE = 0;

using CommandHandler = std::function<int(int, char**)>;

static void PrintGlobalHelp()
{
    nlohmann::json help;
    help["usage"] = "ohos-avsession-manager <command> [options]";
    help["description"] = "CLI tool for managing OHOS AVSession";
    help["commands"] = {
        {"Query Commands", {
            {"list-sessions", "List all session descriptors"}
        }},
        {"Controller Query Commands", {
            {"get-playback-state", "Get AVPlaybackState from controller"},
            {"get-metadata", "Get AVMetaData from controller"},
            {"get-valid-commands", "Get valid commands from controller"}
        }},
        {"Controller Control Commands", {
            {"send-control-command-to-session", "Send control command to session"}
        }}
    };
    help["options"] = "Use 'ohos-avsession-manager <command> --help' for details";
    std::cout << help.dump(JSON_DUMP_INDENT) << std::endl;
}

static nlohmann::json GetListSessionsHelp()
{
    return {
        {"usage", "ohos-avsession-manager list-sessions"},
        {"description", "List all AVSession descriptors"},
        {"parameters", "None"}
    };
}

static nlohmann::json GetPlaybackStateHelp()
{
    return {
        {"usage", "ohos-avsession-manager get-playback-state --session-id <id>"},
        {"description", "Get AVPlaybackState from controller"},
        {"parameters", {
            {"--session-id", "Session ID (required)"}
        }}
    };
}

static nlohmann::json GetMetadataHelp()
{
    return {
        {"usage", "ohos-avsession-manager get-metadata --session-id <id>"},
        {"description", "Get AVMetaData from controller"},
        {"parameters", {
            {"--session-id", "Session ID (required)"}
        }}
    };
}

static nlohmann::json GetValidCommandsHelp()
{
    return {
        {"usage", "ohos-avsession-manager get-valid-commands --session-id <id>"},
        {"description", "Get valid commands from controller"},
        {"parameters", {
            {"--session-id", "Session ID (required)"}
        }}
    };
}

static nlohmann::json GetSendControlCommandToSessionHelp()
{
    return {
        {"usage", "ohos-avsession-manager send-control-command-to-session --session-id <id> --command <cmd> [options]"},
        {"description", "Send control command to session"},
        {"parameters", {
            {"--session-id", "Session ID (required)"},
            {"--command", "Control command (required)"},
            {"--time", "Time in ms: required for seek, optional for fast_forward/rewind (default 15000)"},
            {"--speed", "Speed value: optional for set_speed (default 1.0)"},
            {"--mode", "Loop mode: optional for set_loop_mode (-1 to 4, default 0)"},
            {"--target-mode", "Target loop mode: optional for set_target_loop_mode (-1 to 4, default 0)"},
            {"--asset-id", "Asset ID: required for toggle_favorite"}
        }},
        {"available_commands", {
            "play", "pause", "stop", "play_next", "play_previous",
            "fast_forward", "rewind", "seek", "set_speed",
            "set_loop_mode", "set_target_loop_mode", "toggle_favorite"
        }},
        {"loop_modes", {
            {"-1", "LOOP_MODE_UNDEFINED"},
            {"0", "LOOP_MODE_SEQUENCE"},
            {"1", "LOOP_MODE_SINGLE"},
            {"2", "LOOP_MODE_LIST"},
            {"3", "LOOP_MODE_SHUFFLE"},
            {"4", "LOOP_MODE_CUSTOM"}
        }},
        {"examples", {
            "ohos-avsession-manager send-control-command-to-session --session-id <id> --command play",
            "ohos-avsession-manager send-control-command-to-session --session-id <id> --command seek --time 30000",
            "ohos-avsession-manager send-control-command-to-session --session-id <id> --command set_speed --speed 1.5",
            "ohos-avsession-manager send-control-command-to-session --session-id <id> --command set_loop_mode --mode 2",
            "ohos-avsession-manager send-control-command-to-session --session-id <id> "
            "--command toggle_favorite --asset-id \"song_001\""
        }}
    };
}

static void PrintCommandHelp(const std::string& cmd)
{
    static const std::unordered_map<std::string, nlohmann::json> helpMap = {
        {"list-sessions", GetListSessionsHelp()},
        {"get-playback-state", GetPlaybackStateHelp()},
        {"get-metadata", GetMetadataHelp()},
        {"get-valid-commands", GetValidCommandsHelp()},
        {"send-control-command-to-session", GetSendControlCommandToSessionHelp()}
    };

    auto it = helpMap.find(cmd);
    if (it != helpMap.end()) {
        std::cout << it->second.dump(JSON_DUMP_INDENT) << std::endl;
    } else {
        OutputError(ERR_ARG_INVALID, "Unknown command: " + cmd,
            "Use 'ohos-avsession-manager --help' to see available commands");
    }
}

static bool ParseStringArg(int argc, char** argv, const std::string& argName, std::string& result)
{
    for (int i = 0; i < argc - 1; ++i) {
        if (strcmp(argv[i], argName.c_str()) == 0) {
            result = argv[i + 1];
            return true;
        }
    }
    return false;
}

static bool HasStringArg(int argc, char** argv, const std::string& argName)
{
    std::string dummy;
    return ParseStringArg(argc, argv, argName, dummy);
}


static bool ParseInt64Arg(int argc, char** argv, const std::string& argName,
    int64_t defaultValue, int64_t& result)
{
    std::string value;
    if (!ParseStringArg(argc, argv, argName, value)) {
        result = defaultValue;
        return true;
    }
    if (value.empty()) {
        OutputError(ERR_ARG_INVALID, "Empty value for " + argName,
            "Please provide a valid integer value");
        return false;
    }

    errno = 0;
    char* endPtr = nullptr;
    long long parsed = strtoll(value.c_str(), &endPtr, 10);
    if (errno == ERANGE || parsed > std::numeric_limits<int64_t>::max() ||
        parsed < std::numeric_limits<int64_t>::min()) {
        OutputError(ERR_ARG_INVALID, "Value out of range for " + argName + ": " + value,
            "Range: " + std::to_string(std::numeric_limits<int64_t>::min()) + " to " +
            std::to_string(std::numeric_limits<int64_t>::max()));
        return false;
    }
    if (endPtr == value.c_str() || *endPtr != '\0') {
        OutputError(ERR_ARG_INVALID, "Invalid number format for " + argName + ": " + value,
            "Please provide a valid integer");
        return false;
    }

    result = static_cast<int64_t>(parsed);
    return true;
}

static bool ParseDoubleArg(int argc, char** argv, const std::string& argName,
    double defaultValue, double& result)
{
    std::string value;
    if (!ParseStringArg(argc, argv, argName, value)) {
        result = defaultValue;
        return true;
    }
    if (value.empty()) {
        OutputError(ERR_ARG_INVALID, "Empty value for " + argName,
            "Please provide a valid number value");
        return false;
    }

    errno = 0;
    char* endPtr = nullptr;
    double parsed = strtod(value.c_str(), &endPtr);
    if (errno == ERANGE || parsed == HUGE_VAL || parsed == -HUGE_VAL) {
        OutputError(ERR_ARG_INVALID, "Value out of range for " + argName + ": " + value,
            "Please provide a valid number within double range");
        return false;
    }
    if (!std::isfinite(parsed)) {
        OutputError(ERR_ARG_INVALID, "Invalid number for " + argName + ": " + value,
            "Please provide a finite number (not infinity or NaN)");
        return false;
    }
    if (endPtr == value.c_str() || *endPtr != '\0') {
        OutputError(ERR_ARG_INVALID, "Invalid number format for " + argName + ": " + value,
            "Please provide a valid number");
        return false;
    }

    result = parsed;
    return true;
}

static bool HasHelpArg(int argc, char** argv)
{
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            return true;
        }
    }
    return false;
}

static int HandleListSessions(int argc, char** argv)
{
    if (HasHelpArg(argc, argv)) {
        PrintCommandHelp("list-sessions");
        return 0;
    }

    auto& manager = AVSessionManager::GetInstance();
    std::vector<AVSessionDescriptor> descriptors;
    int32_t ret = manager.GetAllSessionDescriptors(descriptors);
    if (ret != AVSESSION_SUCCESS) {
        OutputError(ret, GetErrorString(ret), "Check if AVSession service is running");
        return 1;
    }
    nlohmann::json data;
    data["sessions"] = nlohmann::json::array();
    for (const auto& desc : descriptors) {
        data["sessions"].push_back(AVSessionDescriptorToJson(desc));
    }
    OutputSuccess(data);
    return 0;
}

static std::shared_ptr<AVSessionController> GetController(const std::string& sessionId)
{
    auto& manager = AVSessionManager::GetInstance();
    std::shared_ptr<AVSessionController> controller;
    int32_t ret = manager.CreateController(sessionId, controller);
    if (ret != AVSESSION_SUCCESS) {
        return nullptr;
    }
    return controller;
}

static int HandleGetPlaybackState(int argc, char** argv)
{
    if (HasHelpArg(argc, argv)) {
        PrintCommandHelp("get-playback-state");
        return 0;
    }

    std::string sessionId;
    if (!ParseStringArg(argc, argv, "--session-id", sessionId)) {
        OutputError(ERR_ARG_MISSING, "Missing required parameter: --session-id",
            "Please provide --session-id parameter");
        return 1;
    }

    if (sessionId.empty()) {
        OutputError(ERR_ARG_INVALID, "session ID cannot be empty",
            "Check if the session ID is valid");
        return 1;
    }

    auto controller = GetController(sessionId);
    if (controller == nullptr) {
        OutputError(ERR_CONTROLLER_NOT_EXIST, "Failed to get controller",
            "Check if the session ID is valid");
        return 1;
    }

    AVPlaybackState state;
    int32_t ret = controller->GetAVPlaybackState(state);
    if (ret != AVSESSION_SUCCESS) {
        OutputError(ret, GetErrorString(ret), "Failed to get playback state");
        return 1;
    }
    OutputSuccess(AVPlaybackStateToJson(state));
    return 0;
}

static int HandleGetMetadata(int argc, char** argv)
{
    if (HasHelpArg(argc, argv)) {
        PrintCommandHelp("get-metadata");
        return 0;
    }

    std::string sessionId;
    if (!ParseStringArg(argc, argv, "--session-id", sessionId)) {
        OutputError(ERR_ARG_MISSING, "Missing required parameter: --session-id",
            "Please provide --session-id parameter");
        return 1;
    }

    auto controller = GetController(sessionId);
    if (controller == nullptr) {
        OutputError(ERR_CONTROLLER_NOT_EXIST, "Failed to get controller",
            "Check if the session ID is valid");
        return 1;
    }

    AVMetaData meta;
    int32_t ret = controller->GetAVMetaData(meta);
    if (ret != AVSESSION_SUCCESS) {
        OutputError(ret, GetErrorString(ret), "Failed to get metadata");
        return 1;
    }
    OutputSuccess(AVMetaDataToJson(meta));
    return 0;
}

static int HandleGetValidCommands(int argc, char** argv)
{
    if (HasHelpArg(argc, argv)) {
        PrintCommandHelp("get-valid-commands");
        return 0;
    }

    std::string sessionId;
    if (!ParseStringArg(argc, argv, "--session-id", sessionId)) {
        OutputError(ERR_ARG_MISSING, "Missing required parameter: --session-id",
            "Please provide --session-id parameter");
        return 1;
    }

    auto controller = GetController(sessionId);
    if (controller == nullptr) {
        OutputError(ERR_CONTROLLER_NOT_EXIST, "Failed to get controller",
            "Check if the session ID is valid");
        return 1;
    }

    std::vector<int32_t> commands;
    int32_t ret = controller->GetValidCommands(commands);
    if (ret != AVSESSION_SUCCESS) {
        OutputError(ret, GetErrorString(ret), "Failed to get valid commands");
        return 1;
    }
    nlohmann::json data;
    data["commands"] = nlohmann::json::array();
    for (int32_t cmd : commands) {
        data["commands"].push_back(GetControlCommandString(cmd));
    }
    OutputSuccess(data);
    return 0;
}

static int32_t GetCommandCode(const std::string& command)
{
    static const std::unordered_map<std::string, int32_t> cmdMap = {
        {"play", AVControlCommand::SESSION_CMD_PLAY},
        {"pause", AVControlCommand::SESSION_CMD_PAUSE},
        {"stop", AVControlCommand::SESSION_CMD_STOP},
        {"play_next", AVControlCommand::SESSION_CMD_PLAY_NEXT},
        {"play_previous", AVControlCommand::SESSION_CMD_PLAY_PREVIOUS},
        {"fast_forward", AVControlCommand::SESSION_CMD_FAST_FORWARD},
        {"rewind", AVControlCommand::SESSION_CMD_REWIND},
        {"seek", AVControlCommand::SESSION_CMD_SEEK},
        {"set_speed", AVControlCommand::SESSION_CMD_SET_SPEED},
        {"set_loop_mode", AVControlCommand::SESSION_CMD_SET_LOOP_MODE},
        {"set_target_loop_mode", AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE},
        {"toggle_favorite", AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE}
    };

    auto it = cmdMap.find(command);
    return (it != cmdMap.end()) ? it->second : -1;
}

struct CommandParams {
    int64_t time = 0;
    double speed = 0.0;
    int32_t mode = 0;
    std::string assetId;
    bool hasTime = false;
    bool hasSpeed = false;
    bool hasMode = false;
    bool hasAssetId = false;
    bool usedDefault = false;
};

static bool ParseTimeArg(int argc, char** argv, CommandParams& params, int64_t defaultTime)
{
    int64_t result = 0;
    if (!ParseInt64Arg(argc, argv, "--time", defaultTime, result)) {
        return false;
    }
    params.time = result;
    params.hasTime = true;
    if (!HasStringArg(argc, argv, "--time")) {
        params.usedDefault = true;
    }
    return true;
}

static bool ParseSeekArg(AVControlCommand& cmd, int argc, char** argv, CommandParams& params)
{
    int64_t result = 0;
    if (!HasStringArg(argc, argv, "--time")) {
        OutputError(ERR_ARG_MISSING, "Command 'seek' requires --time parameter",
            "Example: --time 5000");
        return false;
    }
    if (!ParseInt64Arg(argc, argv, "--time", 0, result)) {
        return false;
    }
    params.time = result;
    params.hasTime = true;
    cmd.SetSeekTime(params.time);
    return true;
}

static bool ParseSpeedArg(AVControlCommand& cmd, int argc, char** argv, CommandParams& params)
{
    double result = 0.0;
    if (!ParseDoubleArg(argc, argv, "--speed", DEFAULT_SPEED, result)) {
        return false;
    }
    params.speed = result;
    params.hasSpeed = true;
    if (!HasStringArg(argc, argv, "--speed")) {
        params.usedDefault = true;
    }
    cmd.SetSpeed(params.speed);
    return true;
}

static bool ParseModeArg(int argc, char** argv, CommandParams& params, const std::string& argName)
{
    int64_t result = 0;
    if (!ParseInt64Arg(argc, argv, argName, DEFAULT_LOOP_MODE, result)) {
        return false;
    }
    if (result > std::numeric_limits<int32_t>::max() ||
        result < std::numeric_limits<int32_t>::min()) {
        OutputError(ERR_ARG_INVALID, "Error: Value out of range for int32_t",
            "Check if the params is valid");
        return false;
    }
    params.mode = static_cast<int32_t>(result);
    params.hasMode = true;
    if (!HasStringArg(argc, argv, argName)) {
        params.usedDefault = true;
    }
    return true;
}

static bool ParseAssetIdArg(int argc, char** argv, CommandParams& params)
{
    std::string assetId;
    if (!ParseStringArg(argc, argv, "--asset-id", assetId)) {
        OutputError(ERR_ARG_MISSING,
            "Command 'toggle_favorite' requires --asset-id parameter",
            "Please provide --asset-id parameter (e.g., --asset-id \"song_001\")");
        return false;
    }
    if (assetId.empty()) {
        OutputError(ERR_ARG_INVALID,
            "Command 'toggle_favorite' requires non-empty --asset-id parameter",
            "Please provide a valid asset-id value");
        return false;
    }
    params.assetId = assetId;
    params.hasAssetId = true;
    return true;
}

static bool SetCommandParameter(AVControlCommand& cmd, int32_t cmdCode,
    int argc, char** argv, CommandParams& params)
{
    params.usedDefault = false;

    switch (cmdCode) {
        case AVControlCommand::SESSION_CMD_FAST_FORWARD:
            if (!ParseTimeArg(argc, argv, params, DEFAULT_FORWARD_TIME)) {
                return false;
            }
            cmd.SetForwardTime(params.time);
            break;
        case AVControlCommand::SESSION_CMD_REWIND:
            if (!ParseTimeArg(argc, argv, params, DEFAULT_REWIND_TIME)) {
                return false;
            }
            cmd.SetRewindTime(params.time);
            break;
        case AVControlCommand::SESSION_CMD_SEEK:
            if (!ParseSeekArg(cmd, argc, argv, params)) {
                return false;
            }
            break;
        case AVControlCommand::SESSION_CMD_SET_SPEED:
            if (!ParseSpeedArg(cmd, argc, argv, params)) {
                return false;
            }
            break;
        case AVControlCommand::SESSION_CMD_SET_LOOP_MODE:
            if (!ParseModeArg(argc, argv, params, "--mode")) {
                return false;
            }
            cmd.SetLoopMode(params.mode);
            break;
        case AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE:
            if (!ParseModeArg(argc, argv, params, "--target-mode")) {
                return false;
            }
            cmd.SetTargetLoopMode(params.mode);
            break;
        case AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE:
            if (!ParseAssetIdArg(argc, argv, params)) {
                return false;
            }
            cmd.SetAssetId(params.assetId);
            break;
        default:
            break;
    }
    return true;
}

static bool ValidateControlCommandArgs(int argc, char** argv, std::string& sessionId,
    std::string& command, int32_t& cmdCode)
{
    bool hasSessionId = ParseStringArg(argc, argv, "--session-id", sessionId);
    bool hasCommand = ParseStringArg(argc, argv, "--command", command);

    if (!hasSessionId) {
        OutputError(ERR_ARG_MISSING, "Missing required parameter: --session-id",
            "Please provide --session-id parameter");
        return false;
    }
    if (sessionId.empty()) {
        OutputError(ERR_ARG_INVALID, "Empty value for --session-id",
            "Please provide a valid session-id value");
        return false;
    }
    if (!hasCommand) {
        OutputError(ERR_ARG_MISSING, "Missing required parameter: --command",
            "Please provide --command parameter");
        return false;
    }
    if (command.empty()) {
        OutputError(ERR_ARG_INVALID, "Empty value for --command",
            "Please provide a valid command value");
        return false;
    }

    cmdCode = GetCommandCode(command);
    if (cmdCode < 0) {
        OutputError(ERR_ARG_INVALID, "Invalid command: " + command,
            "Valid commands: play, pause, stop, play_next, play_previous, "
            "fast_forward, rewind, seek, set_speed, set_loop_mode, "
            "set_target_loop_mode, toggle_favorite");
        return false;
    }
    return true;
}

static nlohmann::json BuildCommandResult(const std::string& command, const CommandParams& params)
{
    nlohmann::json data;
    data["result"] = "success";
    data["command"] = command;

    if (params.hasTime) {
        data["time"] = params.time;
    }
    if (params.hasSpeed) {
        data["speed"] = params.speed;
    }
    if (params.hasMode) {
        data["mode"] = params.mode;
    }
    if (params.hasAssetId) {
        data["assetId"] = params.assetId;
    }
    if (params.usedDefault) {
        data["hint"] = "Default parameter value used. "
            "Specify --time, --speed, --mode, or --target-mode to override.";
    }
    return data;
}

static int HandleSendControlCommandToSession(int argc, char** argv)
{
    if (HasHelpArg(argc, argv)) {
        PrintCommandHelp("send-control-command-to-session");
        return 0;
    }

    std::string sessionId;
    std::string command;
    int32_t cmdCode = 0;

    if (!ValidateControlCommandArgs(argc, argv, sessionId, command, cmdCode)) {
        return 1;
    }

    auto controller = GetController(sessionId);
    if (controller == nullptr) {
        OutputError(ERR_CONTROLLER_NOT_EXIST, "Failed to get controller",
            "Check if the session ID is valid");
        return 1;
    }

    AVControlCommand cmd;
    cmd.SetCommand(cmdCode);

    CommandParams params;
    if (!SetCommandParameter(cmd, cmdCode, argc, argv, params)) {
        return 1;
    }

    int32_t ret = controller->SendControlCommand(cmd);
    if (ret != AVSESSION_SUCCESS) {
        OutputError(ret, GetErrorString(ret), "Failed to send control command");
        return 1;
    }

    OutputSuccess(BuildCommandResult(command, params));
    return 0;
}

static const std::unordered_map<std::string, CommandHandler> g_commandHandlers = {
    {"list-sessions", HandleListSessions},
    {"get-playback-state", HandleGetPlaybackState},
    {"get-metadata", HandleGetMetadata},
    {"get-valid-commands", HandleGetValidCommands},
    {"send-control-command-to-session", HandleSendControlCommandToSession}
};

}

int main(int argc, char** argv)
{
    using namespace OHOS::AVSession::Cli;

    if (argc < MIN_ARG_COUNT) {
        PrintGlobalHelp();
        return 0;
    }

    std::string command = argv[COMMAND_ARG_INDEX];

    if (command == "--help" || command == "-h" || command == "help") {
        if (argc >= SUBCOMMAND_ARG_INDEX + 1) {
            std::string subCommand = argv[SUBCOMMAND_ARG_INDEX];
            auto it = g_commandHandlers.find(subCommand);
            if (it != g_commandHandlers.end()) {
                PrintCommandHelp(subCommand);
            } else {
                OutputError(ERR_ARG_INVALID, "Unknown command: " + subCommand,
                    "Use 'ohos-avsession-manager --help' to see available commands");
                return 1;
            }
        } else {
            PrintGlobalHelp();
        }
        return 0;
    }

    auto it = g_commandHandlers.find(command);
    if (it == g_commandHandlers.end()) {
        OutputError(ERR_ARG_INVALID, "Unknown command: " + command,
            "Use 'ohos-avsession-manager --help' to see available commands");
        return 1;
    }

    return it->second(argc - 1, argv + 1);
}