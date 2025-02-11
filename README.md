# IoTStateFuzzer
Here is the **IoTStateFuzzer** repositorie, where the state machines learned during the experiments will be presented.

# Folder Structure

## 0LearnResults
This folder contains the `Base models` and `State fuzzing models` for 6 devices from 5 vendors mentioned in the paper. 
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

3. **Transition**: In the `.simplify.dot.pdf` file, the *non-black* state transition edges represent the differences between the state fuzzing model and the base model. The characters on the edges represent "input symbol(s) / output symbol".


## Code
This folder contains the code used by **IoTStateFuzzer**, and its directory structure is similar to Figure 4 in the paper.
The key file directory in the folder is as follows:
```
📂 Alphabet  
├── 📂 ui_scan_result
│   ├── 📂 VendorName
│   │   ├── 📄 button_constrain.json
│   │   └── 📄 valuable_button.json

📂 Config  
├── 📄 config_file.py
└── 📄 device_appium_config.py

📂 Learner  
├── 📂 result  
├── 📂 src/main  
│   ├── 📂 java/org/example
│   │   ├── 📄 AlphabetManager.java
│   │   ├── 📄 CacheManager.java
│   │   ├── 📄 Configuration.java
│   │   ├── 📄 IoTStateFuzzer.java
│   │   ├── 📄 Learner.java
│   │   ├── 📄 LogManager.java
│   │   ├── 📄 Mediator.java
│   │   ├── 📄 NetworkManager.java
│   │   ├── 📄 RestartException.java
│   │   └── 📄 Tool.java
│   ├── 📂 resources
│   │   └── 📄 conf.properties
└── 📂 target  

📂 Logger  
└── 📄 mlog.py

📂 Mapper  
├── 📂 Mediator  
│   └── 📄 button_constrain.py  
├── 📂 Monitor  
│   ├── 📄 black_list.json  
│   ├── 📄 dns_mapping.json  
│   ├── 📄 mitm_network.py  
│   ├── 📄 packet_parser.py  
│   ├── 📄 protocol_feature.py  
│   └── 📄 white_list.json  
├── 📂 Operator  
│   ├── 📂 HookScripts
│   │   ├── 📂 VendorName
│   │   │   ├── 📂 js_scripts
│   │   │   ├── 📂 knowledge_files
│   │   │   └── 📂 py_scripts
│   │   └── 📄 mainControl.py  
│   ├── 📄 device.py  
│   └── 📄 pinning_disable.js  

📂 Scripts  
├── 📄 communicate_with_xiaomi_cloud.py
├── 📄 format_tools.py
└── 📄 get_ips.py

📄 learn.py
📄 requirements.txt
```

For specific file descriptions, please refer to the Readme files in each directory.


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
First, run `IoTStateFuzzer.java` in the `Learner` directory to start LearnLib. Then, run `learn_model_main` in the `learn.py` module to start the learning process. This function will first learn the *Base Model* and then proceed to learn the *State Fuzzing Model*.
The learned results will be saved in the `Learner/result` directory.

## Differential Analysis
Run the `difference_annotation.py` script to generate the `.simplify.dot` and `.simplify.dot.pdf` files, where the differences between the *State Fuzzing Model* and the *Base Model* will be highlighted in non-black colors.

