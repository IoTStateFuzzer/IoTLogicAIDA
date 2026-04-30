# Operator Module README

This folder contains the device-operation layer for IoTLogicAIDA. It controls
Android phones through Appium/ADB, starts Frida hooks, records action timing,
and coordinates app-specific hook scripts for different IoT platforms.

## Directory Structure

```text
Operator/
+-- device.py
+-- pinning_disable.js
+-- HookScripts/
|   +-- mainControl.py
|   +-- vendor_name (such as gongniu)/
|   |   +-- action_script.json
|   |   +-- js_scripts/
|   |   +-- knowledge_files/
|   |   +-- py_scripts/
```

## Main Files

### `device.py`

`device.py` is the main entry point and controller in `Operator/`. Its core
class is `DeviceCls`, which controls the app on an Android phone through UI
clicks and hook-based actions.

Main responsibilities:

- Load device, app, and UI-operation configuration.
- Start and stop the target Android app.
- Start and stop Appium server and Appium driver.
- Start and stop Frida server/hook processes.
- Execute configured UI click paths through Appium.
- Execute hook-based actions through `HookScripts/mainControl.py`.
- Capture local traffic with iptables + tcpdump.
- Save per-action logs and packet timing information.

Important methods:

- `start_driver_and_init()`: starts Appium driver and returns the app to home.
- `click_and_save()`: executes a configured UI action and writes timing logs.
- `click_button()`: runs the low-level click path from `valuable_button.json`.
- `hook_and_save()`: executes a hook action and writes timing logs.
- `set_packet_name()`: sets the active pcap name and output packet folder.
- `stop_driver_and_appium_server()`: tears down driver, Frida, Appium, and
  optional app state.

### `pinning_disable.js`

Frida JavaScript loaded by `device.py` when Frida is enabled.

Main responsibilities:

- Disable common SSL pinning implementations.
- Override selected networking behaviors for supported apps.
- Downgrade or expose traffic where the target app supports hookable network
  configuration.

This script is injected with Frida before or during app execution, depending on
the configured `frida_flag`.

### `HookScripts/mainControl.py`

The hook dispatcher used by `DeviceCls.hook_and_save()`.

Main responsibilities:

- Find the app-specific `action_script.json`.
- Map an operation name to the correct Python hook/control script.
- Load the target app name from the UI scan result.
- Start hook-learning scripts as background subprocesses.
- Run hook-replay/control scripts with the latest matching knowledge file.
- Clean and query `knowledge_files/`.

## HookScripts App Folders

Each app/platform folder under `HookScripts/` follows the same general shape:

```text
HookScripts/<app_name>/
+-- action_script.json
+-- js_scripts/
+-- knowledge_files/
+-- py_scripts/
```

### `action_script.json`

Maps an operation name to the Python script that should handle it.

Example:

```json
{
  "user2|local|DeviceControl": "hookHuaweiSmarthome.py",
  "user2|local|DeviceControl|hook": "deviceControl_local.py"
}
```

The normal action is usually used to collect knowledge. The `|hook` action is
usually used to replay or execute the action from an existing knowledge file.

### `py_scripts/`

Python scripts for app-specific hook learning, replay, or direct device control.

Common patterns:

- `hook*.py`: attaches to the app and collects runtime knowledge.
- `deviceControl_local.py`: executes a local-network device-control action.
- `deviceControl_remote.py`: executes a remote/cloud device-control action.
- `config.py`: app-specific constants used by the scripts.

### `js_scripts/`

Frida JavaScript snippets used by the Python hook scripts. These usually collect
runtime values from app internals, such as device tables, share information,
cloud request fields, or QR-code related data.

### `knowledge_files/`

Generated JSON files produced by hook-learning scripts and consumed by replay
scripts.

File names follow this format:

```text
user--channel--action_timestamp.json
```

Example:

```text
user2--local--DeviceControl_1726891985883.json
```

## Operation Name Convention

Internal UI operation names use `|` as the separator:

```text
user|channel|action
user|channel|action|hook
```

Examples:

```text
user1|local|SharePlug
user2|remote|DeviceControl
user2|local|DeviceControl|hook
```

This internal UI name format is used by:

- `device.py`
- `HookScripts/mainControl.py`
- `HookScripts/<app_name>/action_script.json`

Generated file names use `--` instead of `|`:

```text
user--channel--action_timestamp.txt
user--channel--action_timestamp.json
```

Use `ui_name_to_file_name()` when saving a UI name to the filesystem, and
`file_name_to_ui_name()` when mapping a stored file name back to a UI name.

## External Configuration Inputs

This folder depends on configuration and scan results outside `Operator/`.

Important paths referenced by `device.py`:

- `../../Alphabet/ui_scan_result/<scan_folder_name>/valuable_button.json`
- `../Monitor/packets/`
- `../../Logger/`
- `../../Scripts/`
- `Config/device_appium_config.py`
- `Config/config_file.py`

Important path referenced by `HookScripts/mainControl.py`:

- `../../analyse_app/ui_scan_result/<scan_result>/valuable_button.json`

## Typical Runtime Flow

1. Create a `DeviceCls` instance with scan folder, device name, and Frida mode.
2. The instance loads app metadata from `valuable_button.json`.
3. The target app, Frida server/hook, and Appium server are prepared.
4. Call `start_driver_and_init()` to connect Appium and return to the app home.
5. Call `set_packet_name()` before recording action traffic.
6. Run either:
   - `click_and_save()` for Appium-driven UI actions.
   - `hook_and_save()` for Frida/script-driven actions.
7. Logs and captures are saved under the packet/action output folder.
8. Call `stop_driver_and_appium_server()` during cleanup.

## Adding a New App or Action

To add a new supported app/platform:

1. Create `HookScripts/<app_name>/`.
2. Add `action_script.json`.
3. Add required Python scripts under `py_scripts/`.
4. Add Frida JavaScript snippets under `js_scripts/` if needed.
5. Ensure hook-generated JSON files are written under `knowledge_files/`.
6. Add or update the matching UI scan result and `valuable_button.json`.
7. Use the `user|channel|action` UI naming convention in configuration and
   code paths.

To add a new action to an existing app:

1. Add the action to the app's `action_script.json`.
2. Add or update the corresponding Python script.
3. Add any required JS hook script.
4. Add the click path or special action in `valuable_button.json`.
5. Verify that generated logs and knowledge files use the file-name form of
   the same operation, such as `user--channel--action_timestamp`.

## Notes

- `frida_flag=0` disables Frida.
- `frida_flag=1` uses Frida `-F` foreground attach mode.
- `frida_flag=2` uses Frida `-f` spawn mode.
- Local traffic capture depends on iptables rules and NFLOG group 30.
- `tcpdump` writes the pcap on the phone first, then pulls it to the local
  packet folder.
- Appium, ADB, Frida, root permissions, and the configured Android device must
  all be available before running the controller.
