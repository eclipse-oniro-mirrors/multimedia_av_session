# OHOS AVSession Manager CLI Test Document

## Test Overview

This document provides test cases for all 5 commands of the `ohos-avsession-manager` CLI tool.

## Test Environment

- OS: OHOS
- Permissions: `ohos.permission.MANAGE_MEDIA_RESOURCES`, `ohos.permission.MANAGE_MEDIA_RESOURCES_FOR_PUBLIC`
- AVSession service running

## Test Cases

### Query Commands

| ID | Command | Test Case | Expected Result | Status |
|----|---------|-----------|-----------------|--------|
| T01 | list-sessions | `ohos-avsession-manager list-sessions` | JSON with sessions array | PASS/FAIL |
| T02 | list-sessions | `ohos-avsession-manager list-sessions --help` | Help message displayed | PASS/FAIL |

### Controller Query Commands

| ID | Command | Test Case | Expected Result | Status |
|----|---------|-----------|-----------------|--------|
| T03 | get-playback-state | `ohos-avsession-manager get-playback-state --session-id valid_id` | JSON with playback state | PASS/FAIL |
| T04 | get-playback-state | `ohos-avsession-manager get-playback-state` | Error: missing --session-id | PASS/FAIL |
| T05 | get-metadata | `ohos-avsession-manager get-metadata --session-id valid_id` | JSON with metadata | PASS/FAIL |
| T06 | get-metadata | `ohos-avsession-manager get-metadata` | Error: missing --session-id | PASS/FAIL |
| T07 | get-valid-commands | `ohos-avsession-manager get-valid-commands --session-id valid_id` | JSON with commands array | PASS/FAIL |
| T08 | get-valid-commands | `ohos-avsession-manager get-valid-commands` | Error: missing --session-id | PASS/FAIL |

### Controller Control Commands

| ID | Command | Test Case | Expected Result | Status |
|----|---------|-----------|-----------------|--------|
| T09 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command play` | JSON with result: success | PASS/FAIL |
| T10 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command pause` | JSON with result: success | PASS/FAIL |
| T11 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command seek --time 5000` | JSON with result: success | PASS/FAIL |
| T12 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command seek` | Error: missing --time | PASS/FAIL |
| T13 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command fast_forward --time 10000` | JSON with result: success | PASS/FAIL |
| T14 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command rewind --time 5000` | JSON with result: success | PASS/FAIL |
| T15 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_speed --speed 1.5` | JSON with result: success | PASS/FAIL |
| T16 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_loop_mode --mode 3` | JSON with result: success | PASS/FAIL |
| T17 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_target_loop_mode --target-mode 2` | JSON with result: success | PASS/FAIL |
| T18 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command toggle_favorite --asset-id "song_001"` | JSON with result: success | PASS/FAIL |
| T19 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command toggle_favorite` | Error: missing --asset-id | PASS/FAIL |
| T20 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id` | Error: missing --command | PASS/FAIL |
| T21 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --command play` | Error: missing --session-id | PASS/FAIL |
| T22 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command fast_forward` | JSON with hint: default time | PASS/FAIL |
| T23 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command rewind` | JSON with hint: default time | PASS/FAIL |
| T24 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_speed` | JSON with hint: default speed | PASS/FAIL |
| T25 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_loop_mode` | JSON with hint: default mode | PASS/FAIL |
| T26 | send-control-command-to-session | `ohos-avsession-manager send-control-command-to-session --session-id valid_id --command set_target_loop_mode` | JSON with hint: default mode | PASS/FAIL |

### Help Commands

| ID | Command | Test Case | Expected Result | Status |
|----|---------|-----------|-----------------|--------|
| T27 | help | `ohos-avsession-manager --help` | Global help message | PASS/FAIL |
| T28 | help | `ohos-avsession-manager help` | Global help message | PASS/FAIL |
| T29 | help | `ohos-avsession-manager help list-sessions` | Command help message | PASS/FAIL |
| T30 | help | `ohos-avsession-manager list-sessions --help` | Command help message | PASS/FAIL |
| T31 | help | `ohos-avsession-manager help unknown_command` | Error: unknown command | PASS/FAIL |
| T32 | help | `ohos-avsession-manager --help --session-id` | Error: unknown command | PASS/FAIL |

### Error Handling

| ID | Command | Test Case | Expected Result | Status |
|----|---------|-----------|-----------------|--------|
| T33 | invalid | `ohos-avsession-manager unknown_command` | Error: unknown command | PASS/FAIL |
| T34 | no args | `ohos-avsession-manager` | Global help message | PASS/FAIL |
| T35 | permission | Test without required permissions | Error: permission denied | PASS/FAIL |

## Test Summary

| Category | Total Tests | Passed | Failed | Pass Rate |
|----------|-------------|--------|--------|-----------|
| Query Commands | 2 | - | - | - |
| Controller Query Commands | 6 | - | - | - |
| Controller Control Commands | 18 | - | - | - |
| Help Commands | 6 | - | - | - |
| Error Handling | 3 | - | - | - |
| **Total** | **35** | **-** | **-** | **-** |

## Test Execution

### Preconditions

1. AVSession service must be running
2. Required permissions must be granted
3. At least one session must be active for controller tests

### Test Session ID

For tests requiring session ID, use:
- First list sessions: `ohos-avsession-manager list-sessions`
- Use a sessionId from the output for subsequent tests

### Test Automation

Tests can be automated using shell scripts:

```bash
#!/bin/bash

# Test list-sessions
ohos-avsession-manager list-sessions

# Get session ID from output
SESSION_ID=$(ohos-avsession-manager list-sessions | jq -r '.data.sessions[0].sessionId')

# Test with session ID
ohos-avsession-manager get-playback-state --session-id $SESSION_ID
ohos-avsession-manager get-metadata --session-id $SESSION_ID
ohos-avsession-manager get-valid-commands --session-id $SESSION_ID
ohos-avsession-manager send-control-command-to-session --session-id $SESSION_ID --command play
```

## Notes

1. Tests marked with `valid_id` require an actual session ID from a running session
2. Error tests verify that the CLI properly handles invalid inputs
3. Permission tests require testing with different permission configurations
4. Output validation should check JSON structure and required fields