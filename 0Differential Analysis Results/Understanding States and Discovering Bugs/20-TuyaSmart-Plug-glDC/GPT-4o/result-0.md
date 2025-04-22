# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | user1 has bound the device|
|2 | Error state, no actions can be performed|
|3 | user1 has bound the device and shared it with user2|
|4 | user1 has bound the device, shared it with user2, and user2 has successfully controlled the device locally|
|5 | user1 has bound the device, shared it with user2, and user2's permission has been revoked|
|6 | user1 has bound the device, shared it with user2, user2's permission has been revoked, and user1 has removed the device|
|7 | user1 has bound the device, shared it with user2, user2's permission has been revoked, user1 has removed the device, and user1 has re-added the device|
|8 | user1 has bound the device, shared it with user2, user2's permission has been revoked, user1 has removed the device, user1 has re-added the device, and re-shared it with user2|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Device Control
**Impact effect**: User2 can control the device even after user1 has revoked the permission.

**Attack Path** :
1. Attackers accumulate knowledge through "user2|local|DeviceControl" in state s3
2. Replay the "user2|local|DeviceControl" action in state s4
3. Bypass the permission check to enter privilege state s4, where user2 can control the device without permission.