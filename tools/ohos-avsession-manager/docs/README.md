# OHOS AVSession Manager CLI Tool

## Overview

`ohos-avsession-manager` is a command-line interface tool for managing OHOS AVSession. It provides commands to query sessions and query/control session playback state.

## Permissions

The following permissions are required:

- `ohos.permission.MANAGE_MEDIA_RESOURCES` - Required for managing media resources
- `ohos.permission.MANAGE_MEDIA_RESOURCES_FOR_PUBLIC` - Required for public media resource management

## Usage

```bash
ohos-avsession-manager <command> [options]
```

For global help:

```bash
ohos-avsession-manager --help
ohos-avsession-manager help
```

For command-specific help:

```bash
ohos-avsession-manager <command> --help
```

## Commands

### Query Commands

#### list-sessions

List all AVSession descriptors in the system.

**Parameters:** None

**Example:**
```bash
ohos-avsession-manager list-sessions
```

**Output:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "sessions": [
      {
        "sessionId": "session_001",
        "sessionType": "audio",
        "sessionTag": "MusicPlayer",
        "elementName": {
          "bundleName": "com.example.music",
          "moduleName": "entry",
          "abilityName": "MainAbility"
        },
        "isActive": true,
        "isTopSession": true
      }
    ]
  }
}
```

### Controller Query Commands

All commands in this group require `--session-id` parameter.

#### get-playback-state

Get AVPlaybackState from controller.

**Parameters:**
- `--session-id` - Session ID (required)

**Example:**
```bash
ohos-avsession-manager get-playback-state --session-id session_001
```

**Output:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "state": "play",
    "speed": 1.0,
    "position": {
      "elapsedTime": 5000,
      "updateTime": 1234567890
    },
    "loopMode": "list",
    "isFavorite": false,
    "duration": 180000
  }
}
```

#### get-metadata

Get AVMetaData from controller.

**Parameters:**
- `--session-id` - Session ID (required)

**Example:**
```bash
ohos-avsession-manager get-metadata --session-id session_001
```

**Output:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "assetId": "song_001",
    "title": "My Song",
    "artist": "Artist Name",
    "album": "Album Name",
    "duration": 180000
  }
}
```

#### get-valid-commands

Get valid commands from controller.

**Parameters:**
- `--session-id` - Session ID (required)

**Example:**
```bash
ohos-avsession-manager get-valid-commands --session-id session_001
```

**Output:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "commands": ["play", "pause", "stop", "play_next", "play_previous"]
  }
}
```

### Controller Control Commands

#### send-control-command-to-session

Send control command to a specific session.

**Parameters:**
- `--session-id` - Session ID (required)
- `--command` - Control command (required): `play`, `pause`, `stop`, `play_next`, `play_previous`, `fast_forward`, `rewind`, `seek`, `set_speed`, `set_loop_mode`, `set_target_loop_mode`, `toggle_favorite`
- `--time` - Time in milliseconds (required for `seek`, default 15000 for `fast_forward`/`rewind`)
- `--speed` - Playback speed for `set_speed` command (optional, default 1.0)
- `--mode` - Loop mode for `set_loop_mode`: -1=undefined, 0=sequence, 1=single, 2=list, 3=shuffle, 4=custom (optional, default 0)
- `--target-mode` - Target loop mode for `set_target_loop_mode`: -1=undefined, 0=sequence, 1=single, 2=list, 3=shuffle, 4=custom (optional, default 0)
- `--asset-id` - Asset ID for `toggle_favorite` command (required)

**Example:**
```bash
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command play
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command seek --time 5000
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command fast_forward --time 10000
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command set_speed --speed 1.5
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command set_loop_mode --mode 3
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command set_target_loop_mode --target-mode 1
ohos-avsession-manager send-control-command-to-session --session-id session_001 --command toggle_favorite --asset-id "song_001"
```

**Output:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "result": "success",
    "command": "play"
  }
}
```

**Output with parameters (when command uses time/speed/mode):**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "result": "success",
    "command": "seek",
    "time": 5000
  }
}
```

**Output with default parameter hint:**
```json
{
  "type": "result",
  "status": "success",
  "data": {
    "result": "success",
    "command": "fast_forward",
    "time": 15000,
    "hint": "Default parameter value used. Specify --time, --speed, --mode, or --target-mode to override."
  }
}
```

## Output Format

All commands output JSON format:

### Success Response
```json
{
  "type": "result",
  "status": "success",
  "data": {
    ...
  }
}
```

### Error Response
```json
{
  "type": "result",
  "status": "error",
  "errCode": -1,
  "errMsg": "Error message",
  "suggestion": "Suggestion for resolution"
}
```

## Error Codes

| Error Code | Description |
|------------|-------------|
| 0 | Success |
| -1 | General error |
| -1001 | No memory |
| -1002 | Invalid parameter |
| -1003 | Service not exist |
| -1004 | Session listener already exist |
| -1005 | Marshalling error |
| -1006 | Unmarshalling error |
| -1007 | IPC send request error |
| -1008 | Session exceed maximum |
| -1009 | Session not exist |
| -1010 | Command not support |
| -1011 | Controller not exist |
| -1012 | No permission |
| -1013 | Session deactive |
| -1014 | Controller already exist |
| -1015 | Start ability is running |
| -1016 | Ability not available |
| -1017 | Start ability timeout |
| -1018 | Command send exceed max |
| -1022 | Session is exist |
| -1023 | Permission denied |

## Integration

This CLI tool is integrated into the OHOS CLI framework. The executable is located at:

```
/system/bin/cli_tool/executable/ohos-avsession-manager
```