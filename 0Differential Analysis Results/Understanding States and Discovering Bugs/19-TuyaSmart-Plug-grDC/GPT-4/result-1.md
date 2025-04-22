# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | Error state where no operations can be performed successfully|
|3 | User1 has shared the plug with User2, both have control permissions|
|4 | User2 has knowledge of remote device control and can click UI, both users have control permissions|
|5 | User2 has knowledge of remote device control but cannot click UI, User1 has control permissions|
|6 | User2 has knowledge of remote device control but cannot click UI, no user has control permissions|

# Base model report
Every thing is OK.

# Divergent model report
Every thing is OK.

In the analysis of both the base model and the divergent model, all state transitions and permissions are consistent with the expected operations and outcomes defined by the input symbols' semantics. The divergent model introduces states where the attacker (User2) has knowledge of remote device control but this knowledge does not lead to unauthorized control or information leakage, as the system correctly handles the permissions and responses based on the state of the device and user permissions.