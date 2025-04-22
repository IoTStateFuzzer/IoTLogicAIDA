# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device and can control it|
|2 | No device is bound, or no user has control permissions|
|3 | User1 has shared the Camera with user2, but user2 has not yet accepted the share|
|4 | User1 and user2 both have control permissions over the device|
|5 | Device is unbound, no user has control permissions, but user2 has knowledge of the device control API|
|6 | User1 has bound the device again and can control it, user2 has knowledge of the device control API but no control permissions|
|7 | User1 has shared the Camera with user2 and user2 has accepted the share, both have control permissions, user2 has knowledge of the device control API|
|8 | User1 and user2 both have control permissions over the device, user2 has knowledge of the device control API|

# Base model report
Every thing is OK.

# Divergent model report
Every thing is OK.

**Analysis Explanation:**
- **Base Model:** The base model transitions are consistent with the expected behavior of the system under normal operations. Each state transition is triggered by appropriate actions, and the outputs are as expected (e.g., successful device control, sharing, and unsharing).
- **Divergent Model:** The divergent model, despite having the capability of the attacker to perform API hooking on the "AcceptDeviceShare" action, does not show any unauthorized state transitions or unexpected outputs. The states where the attacker has knowledge (KS:[*]) do not lead to unauthorized control or information leakage. The system responses correctly handle the attacker's actions, either by denying unauthorized attempts or by not altering the system state in a way that would compromise security.