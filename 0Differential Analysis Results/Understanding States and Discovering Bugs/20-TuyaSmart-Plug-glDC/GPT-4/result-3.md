# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | Error state where no operations can be executed|
|3 | User1 has shared the plug with user2, both have control permissions|
|4 | User2 has control permission and knowledge to perform local device control via API hooking|
|5 | User2 has control permission but cannot perform local device control via API hooking|
|6 | User2 has knowledge to perform local device control via API hooking but lacks control permission|
|7 | User2 has control permission, can perform local device control via API hooking, but the operation fails|
|8 | User2 has control permission and can perform local device control via API hooking successfully|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Control and Information Leakage
**Impact effect**: User2 retains knowledge and control capabilities even after permissions are supposedly revoked, allowing unauthorized control and potential information leakage about the device state and user1's actions.

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl in state s3.
2. Replay the user2|local|DeviceControl action in state s4, s5, s7, and s8.
3. Bypass the permission revocation to maintain control and knowledge, leading to unauthorized access and potential information leakage.