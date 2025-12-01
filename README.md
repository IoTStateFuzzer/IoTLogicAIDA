# IoTLogicAIDA
Here is the **IoTLogicAIDA** repositorie, where the state machines learned during the experiments will be presented.

# Folder Structure

## 0Differential Analysis Results
This folder contains the differential analysis results and findings from the experiments. It includes three main stages of analysis:

Folder Structure:
```
📂 0Differential Analysis Results
├── 📂 0LLMAssistDFResults
│   └── 📂 each_vendor/ (broadlink, gongniu, tuya, VendorA, xiaomi, etc.)
├── 📂 Understanding Abstract Symbols
│   └── 📂 each_vendor/ (BroadLink, BULL, Tuya, Vendor A, Xiaomi, etc.)
└── 📂 Understanding States and Discovering Bugs
    └── 📂 ExperimentNumber/ (1-20, corresponding to Table 4 in the paper)
```

Subfolder Description:

1. **0LLMAssistDFResults**: Contains the end-to-end differential analysis results generated with LLM assistance for each devices.

2. **Understanding Abstract Symbols**: Provides analysis and explanation of the abstract symbols used in the state machines for each vendor.

3. **Understanding States and Discovering Bugs**: Contains detailed analysis of the states in each model and identified bugs for each experiment (corresponding to the experiment numbers in the folder names).


## 0LearnResults
This folder contains the `Base models` and `Divergent models` for 6 devices from 5 vendors mentioned in the paper. 
The folder numbers correspond to the experimental results in Table 4 (Results of model learning experiments) of the article.
These models are used for analyzing and testing the behavior of the devices under various conditions, with a focus on identifying potential logic vulnerabilities and bugs.

Folder Structure:
```
📂 0LearnResults
├── 📂 ExperimentsNumberinTable4
│   │   ├── 📄 model.dot
│   │   ├── 📄 model.pdf
│   │   ├── (📄 model.simplify.dot)
│   │   └── (📄 model.simplify.dot.pdf)
```

File Description:

1. **.dot** file: The dot files represent the state machine learned by the Learner (LearnLib). 

2. **.dot.pdf** file: The PDF files correspond to the state machine visualized using the dot file.

2. **.simplify.dot** file: The dot files after simplifying and annotating the dot file.

3. **.simplify.dot.pdf** file: The PDF files after simplifying and annotating the dot file. 

State Machine Details:

1. **State**: The `Initial state` for all models is `0`. The `Error state` is represented as either `state 1` or `state 2`, depending on the result from the learning process.

2. **Symbol**: `NoElement` represents the special response `N/A` as described in the paper. 
`CLS_-1` indicates that the execution of the action should always leads to the same outcome and does not introduce any vulnerabilities, so no categorization is made for the action's output symbol.

3. **Transition**: In the `.simplify.dot.pdf` file, the *non-black* state transition edges represent the differences between the state exploration model and the base model. The characters on the edges represent "input symbol(s) / output symbol".


## Code
This folder contains the code used by **IoTLogicAIDA**, and its directory structure is similar to Figure 4 in the paper.
The key file directory in the folder is as follows:
```
📂 Code
├── 📂 Alphabet  
│   └── 📂 ui_scan_result
│       └── 📂 VendorName (broadlink, xiaomi, tuya, gongniu, etc.)
│           ├── 📄 button_constrain.json
│           └── 📄 valuable_button.json
├── 📂 Config  
│   ├── 📄 config_file.py
│   └── 📄 device_appium_config.py
├── 📂 Learner  
│   ├── 📄 pom.xml
│   ├── 📄 README.md
│   ├── 📂 src/main  
│   │   ├── 📂 java/org/example
│   │   │   ├── 📄 AlphabetManager.java
│   │   │   ├── 📄 CacheManager.java
│   │   │   ├── 📄 Configuration.java
│   │   │   ├── 📄 IoTStateFuzzer.java
│   │   │   ├── 📄 Learner.java
│   │   │   ├── 📄 LogManager.java
│   │   │   ├── 📄 Mediator.java
│   │   │   ├── 📄 NetworkManager.java
│   │   │   ├── 📄 RestartException.java
│   │   │   └── 📄 Tool.java
│   │   └── 📂 resources
│   │       └── 📄 conf.properties
│   └── 📂 target  
├── 📂 Logger  
│   └── 📄 mlog.py
├── 📂 Mapper  
│   ├── 📂 Mediator  
│   │   └── 📄 button_constrain.py  
│   ├── 📂 Monitor  
│   │   ├── 📄 dns_mapping.json  
│   │   ├── 📄 mitm_network.py  
│   │   ├── 📄 packet_parser.py  
│   │   └── 📄 protocol_feature.py  
│   └── 📂 Operator  
│       ├── 📂 HookScripts
│       │   ├── 📂 each_vendor/ (broadlink, gongniu, tuya, xiaomi, etc.)
│       │   └── 📄 mainControl.py  
│       ├── 📄 device.py  
│       └── 📄 pinning_disable.js  
├── 📂 Scripts  
│   ├── 📄 communicate_with_xiaomi_cloud.py
│   ├── 📄 difference_annotation.py
│   ├── 📄 format_tools.py
│   └── 📄 get_ips.py
├── 📄 learn.py
└── 📄 requirements.txt
```

Module Descriptions:

1. **Alphabet**: Stores UI scanning results and defines input symbols for each vendor's device. Contains configuration files for button constraints and valuable actions.

2. **Config**: Configuration files for the learning framework, including device-specific Appium configurations and general system settings.

3. **Learner**: Java-based learning engine using LearnLib library. Contains the state machine learning algorithm implementation and model generation logic. The `IoTStateFuzzer.java` is the main entry point for starting the learning process.

4. **Logger**: Logging utilities for recording system events and debugging information during the learning and testing process.

5. **Scripts**: Utility scripts including cloud communication, traffic annotation, and IP management.

For specific file descriptions, please refer to the Readme files in each directory.



## Appendix
This folder contains supplementary materials and resources related to the experiments:

Folder Structure:
```
📂 Appendix
├── 📂 1. Click Path Inference
│   ├── 📄 UI_Inference_Prompt.pdf
│   └── 📄 UI_Inference_Result.pdf
├── 📂 2. Abstract Alphabet Used in Experiments
└── 📂 3. Differential Analysis Prompts
```

Subfolder Description:

1. **1. Click Path Inference**: Contains prompts and results related to UI click path inference used in the experiments.

2. **2. Abstract Alphabet Used in Experiments**: Provides documentation of the abstract alphabets (input and output symbols) utilized during the state machine learning experiments.

3. **3. Differential Analysis Prompts**: Contains the prompts used for performing differential analysis on the learned state machines.


# Start
## Set up the environment
In the experiments described in this paper, we used the following setup: Ubuntu 16.04, two wireless network cards (used as APs), and four rooted Android phones (equipped with Appium). 

The Ubuntu 16.04 system requires Python 3.8.11 and openjdk 11.0.10 environments. The Python environment need have the libraries installed as specified in the `requirements.txt` file, and the Java environment requires the installation of LearnLib 0.17.0. Additionally, Ubuntu needs to have mitmproxy 6.0.2, Appium 1.22.0, ADB 1.0.41, and Wireshark 3.4.2 installed. Please refer to the respective official websites for detailed installation guidance. 

The Android phones need to have Appium 1.22.0 and Frida 16.1.4 installed. Again, refer to the corresponding official websites for detailed installation guidance.

## UI Interface Analysis
Analyze the actions of the APP to be checked that you want to examine (to get **input symbols**), and fill in the `valuable_button.json` and `button_constraint.json` files in the folder. For specific templates, please refer to the [Readme]().

## Traffic Collection and Preprocessing
Run the `create_database_manually` function in `learn.py`. This function will loop through the `createDatabaseActionOrder` section in `valuable_button.json` for `test_round` rounds, clicking accordingly and collecting traffic during the process. The captured traffic will be saved in the `Mapper/Monitor/packets` directory.

Run the `pre_parse` function in `packet_parser.py` to analyze the recently captured traffic and obtain the **output symbols**.


## Learning Model
First, run `IoTStateFuzzer.java` in the `Learner` directory to start LearnLib. Then, run `learn_model_main` in the `learn.py` module to start the learning process. This function will first learn the *Base Model* and then proceed to learn the *State Exploration Model*.
The learned results will be saved in the `Learner/result` directory.

## Differential Analysis
Run the `difference_annotation.py` script to generate the `.simplify.dot` and `.simplify.dot.pdf` files, where the differences between the *State Exploration Model* and the *Base Model* will be highlighted in non-black colors.

