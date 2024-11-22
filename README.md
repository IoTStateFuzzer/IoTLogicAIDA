# IoTStateFuzzer
Here is the IoTStateFuzzer repositorie, where the state machines learned during the experiments will be presented.

# File Structure

## 0LearnResults
This folder contains the `Base models` and `State fuzzing models` for 6 devices from 5 vendors mentioned in the paper. These models are used for analyzing and testing the behavior of the devices under various conditions, with a focus on identifying potential logic vulnerabilities and bugs.

In this folder, the files are stored as follows:
```
0LearnResults - Vendor (- Device) - BaseModel (- Special category) - .dot and .pdf
                                  - StateFuzzing (- Special category) - Depth of Wp-Method - Hookable action - .dot and .pdf
```

File Description:

1. **.dot file**: The dot files represent the state machine learned by the Learner. 

2. **.pdf file**: The PDF files correspond to the state machine visualized using the dot files.

State Machine Details:

1. State: The `Initial state` for all models is `0`. The `Error state` is represented as either `state 1` or `state 2`, depending on the result from the learning process.

2. Symbol: `NoElement` represents the special response `N/A` as described in the paper. 
`CLS_-1` indicates that the execution of the action always leads to the same outcome and does not introduce any vulnerabilities, so no categorization is made for the action's output symbol.
