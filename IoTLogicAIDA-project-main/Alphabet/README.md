# Alphabet

Alphabet is a Python-based automation framework for exploring and operating Android smart-home apps. It combines Appium, ADB, LLM-based decision making, and predefined UI action libraries to support workflows such as adding devices, controlling devices, sharing devices, accepting invitations, removing devices, and restoring app/device state.

This repository is not organized as a packaged Python library. It is a runtime and experiment workspace: Python files provide the automation engine, while JSON files under `ui_scan_result/` store app-specific action libraries and action constraints.

## Project Layout

```text
Alphabet/
|-- scan.py
|-- multidevice_manager.py
|-- config.py
|-- analyse.py
|-- clean_appium.py
|-- chat_.py
|-- page_signatures.txt
|-- Logger/
|   `-- mlog.py
|-- ui_scan_result/
|   |-- valuable_button_example.json
|   |-- broadlink/
|   |   |-- valuable_button.json
|   |   `-- button_constrain.json
|   |-- gongniu/
|   |   |-- valuable_button.json
|   |   `-- button_constrain.json
|   |-- tuya/
|   |   |-- valuable_button.json
|   |   `-- button_constrain.json
|   `-- xiaomi/
|       |-- valuable_button.json
|       `-- button_constrain.json
`-- test/
```

## Architecture

The project is organized into three layers:

1. Environment layer: Android devices, ADB, Appium, UiAutomator2, and LLM API access.
2. Execution layer: `SmartHomeAppScanner` in `scan.py`, which handles page recognition, LLM decisions, clicks, input, waits, screenshots, and ADB commands on a single phone.
3. Orchestration layer: `MultiDeviceManager` in `multidevice_manager.py`, which coordinates task order, shared data, and recovery across multiple phones or accounts.

The action knowledge base is stored under `ui_scan_result/<app_name>/`. Each app usually has two key files:

- `valuable_button.json`: describes valuable actions that can be executed in the app.
- `button_constrain.json`: describes prerequisites and conflicts between actions.

## Core Files

### `scan.py`

`scan.py` is the main single-device executor. Its core class is `SmartHomeAppScanner`.

It is responsible for:

- Starting an Appium server from the device configuration.
- Initializing an Android `UiAutomator2` driver.
- Collecting interactable elements from the current page.
- Sending page elements, user goals, and historical feedback to the LLM for next-step decisions.
- Executing clicks, text input, coordinate taps, back navigation, refreshes, waits, screenshots, and ADB commands.
- Recording page signatures for page-change and loop detection.
- Writing learned operation flows back to configuration files.

The main entry point is:

```python
scanner.execute_user_operation(user_command, user_info)
```

`user_command` is a dictionary. The first key is the action type, and the value is the detailed operation intent:

```python
{"AcceptDeviceShare": "Open the message center and accept the device sharing invitation."}
```

`user_info` identifies which user and side are executing the operation:

```python
{"user": "user2", "scope": "remote"}
```

### `multidevice_manager.py`

`multidevice_manager.py` is the multi-device orchestration layer. Its core class is `MultiDeviceManager`.

It is responsible for:

- Creating one `SmartHomeAppScanner` for each device.
- Managing devices by phone number or account identifier.
- Dispatching task steps to different devices.
- Storing shared data and execution feedback across devices.
- Calling reset logic when a task fails.

This file currently works more like an experimental orchestration entry point. Because `execute_user_operation` in `scan.py` currently expects both `user_command` and `user_info`, the task structure passed by the manager must stay aligned with that method signature.

### `config.py`

`config.py` stores local runtime configuration, including:

- LLM/API placeholder values.
- `operation_keywords`, used to map natural-language operation names to canonical action names.
- Device configs such as `user1_device_config` and `user2_device_config`.
- Base app configs such as `tuya_config` and `gongniu_config`.

Before running the project, replace placeholders such as:

- `api_key`
- `udid`
- `phoneNumber`
- `appPackage`
- `appActivity`
- `appium_port`
- `system_port`

For multi-device runs, each device should use a different `appium_port` and `system_port`.

### `ui_scan_result/`

This is the action-library directory. The repository currently includes configurations for BroadLink, Gongniu, Tuya, and Xiaomi.

Each app directory contains:

- `valuable_button.json`: action definitions.
- `button_constrain.json`: action constraints.

`ui_scan_result/valuable_button_example.json` documents the expected format of `valuable_button.json` and common action types.

### `analyse.py`

`analyse.py` parses results produced by an external UI scanning tool. It reads XML files and screenshot-name metadata from `temp_scan_result/`, extracts clickable elements, and generates clickable-element maps and Activity transition graphs.

It is a helper for building action libraries, not the main runtime entry point.

### `clean_appium.py`

`clean_appium.py` releases an occupied Appium port:

```bash
python clean_appium.py 4724
```

### `Logger/mlog.py`

`Logger/mlog.py` provides simple logging helpers. Logs are written to `Logger/program_YYYYMMDD.log`. Log files are ignored by `.gitignore`.

### `chat_.py`

`chat_.py` is a lightweight wrapper around an OpenAI-compatible chat completion API. The main automation flow mostly uses `ChatZhipuAI` inside `scan.py` and `multidevice_manager.py`.

## Action Library Structure

`valuable_button.json` is the most important configuration file. It describes an app's metadata, reset actions, database construction order, auxiliary actions, and executable actions for `user1` and `user2` under both `local` and `remote` scopes.

Typical structure:

```jsonc
{
  "appPackage": "com.example.app",
  "appStartActivity": ".MainActivity",
  "homePage": ".HomeActivity",
  "appName": "Example App",
  "version": "1.0.0",
  "removeDeviceSleepTime": 5,
  "addDeviceSleepTime": 2,
  "resetActions": [],
  "hookableActions": [],
  "overlookActions": [],
  "createDatabaseActionOrder": [],
  "Special": {},
  "user1": {
    "local": {},
    "remote": {}
  },
  "user2": {
    "local": {},
    "remote": {}
  }
}
```

Action names use this format:

```text
user|channel|ActionName
```

Examples:

```text
user1|local|AddDevice
user1|local|SharePlug
user2|remote|AcceptInvite
user2|remote|DeviceControl
```

Meaning:

- `user1` / `user2`: the account or device actor.
- `local`: the local side, usually the phone that directly manages the IoT device.
- `remote`: the remote side, usually another account or phone used to accept invitations, perform remote control, or observe state changes.
- `ActionName`: the canonical action name, such as `AddDevice`, `RemoveDevice`, `DeviceControl`, `SharePlug`, or `AcceptInvite`.

Each action is composed of numbered steps:

```jsonc
"DeviceControl": {
  "1": {
    "xpath": "//android.widget.TextView[@text='Device']",
    "description": "click device"
  },
  "2": {
    "resource_id": "com.example:id/switch",
    "description": "click switch",
    "waiting_time": 1
  }
}
```

Common step fields:

- `xpath`: locate an element by XPath.
- `resource_id`: locate an element by Android resource id.
- `posi_x` / `posi_y`: tap by screen coordinates.
- `description`: log description.
- `input_text`: text for an input field.
- `waiting_time`: wait time.
- `wait_until_exist`: wait until an element appears.
- `refresh`: refresh the current page state.
- `bottom`: scroll to the bottom before executing the step.
- `back`: press Back.
- `back_to_home`: return to the home page after the step.
- `getScreenShot`: capture a screenshot.
- `can_not_exist`: mark the element as optional, usually for optional dialogs.
- `otherPhoneAction`: trigger an action on another phone.
- `exist_and_do`: execute another action if the element exists.
- `not_exist_and_do`: execute another action if the element does not exist.
- `command`: execute an ADB command instead of a UI operation.

## Action Constraints

`button_constrain.json` usually contains:

```jsonc
{
  "constrain_dict": {},
  "conflict_dict": {}
}
```

`constrain_dict` describes prerequisites. For example, a `DeviceControl` action may require `AddDevice` to be completed first.

`conflict_dict` describes conflicts or mutually exclusive actions. For example, the same invitation action should not be repeated, and removing a device conflicts with later control actions that depend on the device.

When adding a new action library, update the constraint file as well. Without constraints, multi-device orchestration can easily generate invalid action orders.

## Runtime Flow

### Single-Device Flow

1. Prepare the device config and app config in `config.py`.
2. Create a `SmartHomeAppScanner`.
3. The scanner starts Appium and connects to the device.
4. The scanner navigates back to the app home page.
5. The scanner collects elements from the current page.
6. The LLM chooses the next step based on the user goal and page elements.
7. The scanner executes a click, input, wait, or ADB command.
8. The scanner records page signatures, screenshots, feedback, and operation steps.
9. The loop continues until the LLM marks the operation complete or the flow fails.

### Multi-Device Flow

1. `MultiDeviceManager` reads a base app config and multiple device configs.
2. It creates one `SmartHomeAppScanner` for each device.
3. It selects the target device for each task step.
4. The target device executes the corresponding action.
5. If the step involves QR codes, invitations, sharing, or other cross-device data, the manager stores shared data.
6. The task succeeds when all steps complete; on failure, the manager resets devices.

## Environment Setup

Python dependencies:

```bash
pip install appium-python-client selenium requests openai langchain-community langchain-core
```

Android/Appium dependencies:

```bash
npm install -g appium
appium driver install uiautomator2
adb devices
```

Before running, confirm that:

- USB debugging is enabled on the phone.
- `adb devices` can see the device.
- The target app is installed.
- The package name and launch Activity are correct.
- Appium ports do not conflict.
- LLM API keys have been replaced with real values.

## Single-Device Example

The example below uses `gongniu_config` and `user1_device_config`, which already exist in `config.py`. Replace placeholders with real device information before running.

```python
from scan import SmartHomeAppScanner
from config import gongniu_config, user1_device_config

scanner = SmartHomeAppScanner(
    APP_json_config=gongniu_config,
    device_config=user1_device_config,
    explore_horizontal=True,
    save_path="gongniu_test"
)

scanner.execute_user_operation(
    {"AddDevice": "Add a smart plug to the current account."},
    user_info={"user": "user1", "scope": "local"}
)

scanner.driver.quit()
```

You can place the example in the `__main__` block of `scan.py`, then run:

```bash
python scan.py
```

## Multi-Device Example

```python
from multidevice_manager import MultiDeviceManager
from config import gongniu_config, user1_device_config, user2_device_config

manager = MultiDeviceManager(
    base_config=gongniu_config,
    device_configs=[user1_device_config, user2_device_config]
)

task = {
    "name": "share device and accept invitation",
    "steps": [
        {
            "device": user1_device_config["phoneNumber"],
            "operation": {"SharePlug": "Share the plug with user2."}
        },
        {
            "device": user2_device_config["phoneNumber"],
            "operation": {"AcceptDeviceShare": "Accept the device sharing invitation."}
        }
    ]
}

manager.execute_task(task)
```

Note: the current experimental code in `multidevice_manager.py` must stay aligned with the method signature in `scan.py`. If direct execution raises an argument error, add `user_info` to each manager step or update the manager call to pass arguments according to `execute_user_operation`.

## Generated Files

Runtime may generate or update:

- `page_signatures.txt`: page state signatures.
- `Loop_page_signatures.txt`: page signatures used for loop detection.
- `operation_flow_config.json`: saved operation flow config.
- `screenshot/` and `screenshots/`: runtime screenshots.
- `Logger/program_YYYYMMDD.log`: log file.
- `temp_scan_result/`: temporary directory used by `analyse.py` when parsing scan results.

## Building a New App Action Library

1. Create a new app directory under `ui_scan_result/`.
2. Use `ui_scan_result/valuable_button_example.json` as the reference for `valuable_button.json`.
3. Fill in app metadata: package name, launch Activity, home Activity, version, and wait times.
4. Configure `Special` actions first, such as `restartApp`, `refresh`, `BackHome`, and `ClickBack`.
5. Add business actions under `user1.local`, `user1.remote`, `user2.local`, and `user2.remote`.
6. Create `button_constrain.json` based on action dependencies.
7. Run and refine actions with `SmartHomeAppScanner`.
8. Add stable actions to `createDatabaseActionOrder` for later modeling or batch execution.

## Development Notes

- The project still contains placeholder API keys, device identifiers, and account information. Replace them before real runs.
- Do not commit real API keys, phone numbers, or device account data.
- Some historical comments and strings have encoding issues, but the main runtime structure is still clear from class names, function names, and JSON fields.
- The project currently targets Android only. There is no iOS execution path.
- `valuable_button.json` is the long-term place for stable action knowledge. After an LLM-guided exploration succeeds, encode stable steps there.
