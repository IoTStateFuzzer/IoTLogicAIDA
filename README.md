# IoTLogicAIDA
IoTLogicAIDA is a black-box vulnerability discovery tool for consumer IoT systems. It targets business logic flaws caused by complex IoT scenarios and heterogeneous protocols, using automata inference to model system behavior and LLM-assisted differential analysis to reason about semantic risks such as unauthorized control and data leakage.

This repository contains two main parts:

- `IoTLogicAIDA-project-main/`: source code for data collection, model learning, traffic parsing, device operation, and differential analysis.
- `Evaluation/`: experiment artifacts, learned state machines, threshold evaluation data, and differential-analysis results.

## Repository Structure

```text
.
|-- README.md
|-- Evaluation/
|   |-- ConstructedStateMachines/
|   |-- CPE/
|   |   |-- Step2/
|   |   |-- Step3/
|   |   `-- threshold_evaluation.py
|   `-- DifferentialAnalysisResults/
|       |-- Full Process/
|       `-- Three Steps/
`-- IoTLogicAIDA-project-main/
    |-- Alphabet/
    |-- Config/
    |   |-- config_file.py
    |   `-- device_appium_config.py
    |-- DFChecker/
    |   |-- DifferentialAnalyst.py
    |   |-- PromptFiles/
    |   `-- material/
    |-- Learner/
    |-- Logger/
    |   `-- mlog.py
    |-- Mapper/
    |   |-- Mediator/
    |   |-- Monitor/
    |   `-- Operator/
    |-- Scripts/
    |-- learn.py
    `-- requirements.txt
```

## Main Modules

### `IoTLogicAIDA-project-main/learn.py`

Main Python entry point for the learning workflow. It coordinates socket communication with the Java learner, loads abstract input symbols, drives Android devices through the operator layer, starts traffic collection, parses action responses, and sends output symbols back to LearnLib.

Important functions:

- `create_database_manually(...)`: collects traffic data by executing configured actions.
- `learn_model_main(...)`: runs the model-learning workflow with LearnLib.
- `check_response_of_specific_action_list(...)`: checks responses for selected action sequences.

### `Alphabet/`

Stores UI scan results and action definitions. The learning workflow expects files such as `valuable_button.json` under `Alphabet/ui_scan_result/<scan_result_name>/`.

Typical configuration items include:

- `resetActions`: actions used to restore the device/app state.
- `overlookActions`: actions ignored during alphabet construction.
- `hookableActions`: actions that can be executed through hook scripts.
- User and network-distance action definitions, such as `user1/local/...` and `user2/remote/...`.

### `Config/`

Runtime configuration for devices, network interfaces, and external tools.

- `config_file.py`: mitmproxy path, wireless-card mapping, Appium path, Frida server path, system password, abstraction thresholds, and traffic-wait settings.
- `device_appium_config.py`: Android phone/Appium capability definitions, UDID mapping, Appium ports, unlock passwords, and helper functions for resolving phone/device IP addresses.

Before running experiments, replace placeholder values such as Android `udid`, wireless interface names, and tool paths with the local environment values.

### `Mapper/`

Connects UI actions to concrete device execution and network observations.

- `Mapper/Operator/`: controls Android apps with Appium/ADB, starts Frida hooks, and dispatches app-specific hook scripts. See `IoTLogicAIDA-project-main/Mapper/Operator/README.md` for details.
- `Mapper/Monitor/`: starts MITM/tshark capture and parses pcap/pcapng traffic into BTBs and further maps them to abstract output symbols.
- `Mapper/Mediator/`: handles input-sequence constraints and action-order checks.

### `Learner/`

Java-based LearnLib learner. The Python side communicates with this component through sockets. The learner requests input symbols, sends queries, and receives abstract output symbols from `learn.py`.

### `DFChecker/`

LLM-assisted differential-analysis module.

- `DifferentialAnalyst.py`: orchestrates abstract-symbol understanding, state understanding, and bug discovery.
- `PromptFiles/`: prompt templates for state interpretation, traffic-symbol explanation, voting, and differential analysis.
- `material/`: vendor-specific FSMs, JSON inputs, traffic semantic mappings, and symbol-effect files.

### `Evaluation/`

Stores experiment outputs and evaluation materials.

- `ConstructedStateMachines/`: learned `.dot` state machines and generated `.pdf` visualizations.
- `CPE/`: threshold evaluation data and figures for step-level filtering behavior.
- `DifferentialAnalysisResults/`: full-process and three-step LLM differential-analysis results.

## Environment

The original experiment environment used:

- Ubuntu 16.04
- Python 3.8.11
- OpenJDK 11.0.10
- LearnLib 0.17.0
- mitmproxy 6.0.2
- Appium 1.22.0
- ADB 1.0.41
- Wireshark/tshark 3.4.2
- Frida 16.1.4
- Rooted Android phones with Appium and Frida server installed
- Two wireless network cards, used as local and remote APs

Python dependencies are listed in:

```text
IoTLogicAIDA-project-main/requirements.txt
```

Install them with:

```bash
cd IoTLogicAIDA-project-main
python3.8 -m pip install -r requirements.txt
```

Current Python dependencies include:

- `tqdm`
- `Appium-Python-Client`
- `selenium`
- `frida`
- `pyshark`

Some modules also use system tools such as `adb`, `appium`, `frida`, `mitmdump`, `tshark`, `tcpdump`, `iptables`, and `dot`/Graphviz. Make sure these commands are installed and available in the configured paths.

## Configuration Checklist

Before running an experiment:

1. Update `Config/config_file.py`.
   - Set `mitm_path`.
   - Set the `local` and `remote` wireless interface names in `wireless_card_dict`.
   - Set `appium_path`.
   - Set `frida_server_path`.
   - Adjust abstraction thresholds if needed.

2. Update `Config/device_appium_config.py`.
   - Replace every placeholder `udid` with the real Android device UDID.
   - Check Appium ports and device names.
   - Confirm each phone is mapped to the intended `user` and `distance`.
   - Update `device_ip_list` for the IoT device under test.

3. Prepare UI scan results under `Alphabet/ui_scan_result/<scan_result_name>/`.
   - Fill in `valuable_button.json`.
   - Fill in button constraints such as `button_constrain.json` if required by the experiment.

4. Prepare Android devices.
   - Enable USB debugging.
   - Confirm `adb devices` lists all phones.
   - Install and start the proper Frida server on each rooted phone.
   - Install and configure the target IoT app.

5. Prepare network capture.
   - Confirm both wireless AP interfaces are available.
   - Confirm MITM, tshark, tcpdump, and iptables permissions.

## Typical Workflow

### 1. Collect traffic and build an action database

Use `create_database_manually(...)` in `learn.py`. This executes action orders from `valuable_button.json`, records traffic, and saves packets under the monitor packet directory.

Example usage from a Python shell or a small runner script:

```python
from learn import create_database_manually

create_database_manually(
    scan_result_name="your_scan_result_name",
    database_name="your_database_name",
    test_round=5,
    reset_at_each_round=False,
)
```

### 2. Pre-parse captured traffic

Use `pre_parse(...)` from `Mapper/Monitor/packet_parser.py` to parse collected traffic and generate abstract output-symbol data.

```python
from Mapper.Monitor.packet_parser import pre_parse

pre_parse(["your_database_name"])
```

### 3. Start the Java learner

Run the LearnLib entry point in `Learner/` first. The Python learner client expects the Java learner server to be available on the configured socket.

The Python side uses:

- local port: `7011`
- learner server: `127.0.0.1:9999`

### 4. Learn the model

After the Java learner is running, start the Python learning workflow:

```python
from learn import learn_model_main

learn_model_main(
    scan_result_name="your_scan_result_name",
    database="your_database_name",
    learn_dir_name="learn_your_target",
)
```

Learned models are generated by the learner and can be compared with the state machines stored in `Evaluation/ConstructedStateMachines/`.

### 5. Run differential analysis

Use `DFChecker/DifferentialAnalyst.py` for LLM-assisted analysis. The module supports:

- abstract-symbol understanding
- state understanding
- bug discovery
- full differential-analysis workflow

Key functions include:

- `understanding_btb_only(...)`
- `understanding_states_only(...)`
- `discovering_bugs_only(...)`
- `differential_analysis_main(...)`

## State Machine Files

State-machine artifacts are stored under `Evaluation/ConstructedStateMachines/<experiment_id>/`.

Common files:

- `*.dot`: learned state machine in Graphviz DOT format.
- `*.dot.pdf`: rendered visualization of the DOT model.
- `*.simplify.dot`: simplified and annotated DOT model.
- `*.simplify.dot.pdf`: rendered simplified model.

Conventions:

- Initial state is usually `0`.
- Error states are commonly represented as state `1` or state `2`, depending on the learning result.
- `NoElement` represents an `N/A` response.
- `CLS_-1` indicates an action whose output does not require finer classification.
- In simplified PDFs, non-black edges usually highlight differences between base models and state-exploration models.

## Notes

- This repository contains experiment code and data. Running the full workflow requires real rooted Android devices, physical IoT devices, AP-capable wireless cards, and environment-specific credentials/configuration.
- Several paths in the source code are absolute or environment-specific. Review configuration files before running commands.
- Do not commit real device UDIDs, passwords, cloud credentials, or private network information.
- The root `README.md` describes the current repository layout. For module-specific details, refer to the `README.md` files in each subdirectory, such as `Mapper/Operator/README.md` for operator details.