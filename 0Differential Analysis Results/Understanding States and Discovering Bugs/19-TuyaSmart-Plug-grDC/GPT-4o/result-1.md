# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | user1 has bound the device|
|2 | Error state where no actions are executable|
|3 | user1 has bound the device and shared it with user2|
|4 | user1 has bound the device, shared it with user2, and user2 has successfully controlled the device remotely|
|5 | user1 has bound the device, shared it with user2, revoked user2's permission, and user2 has knowledge for remote control|
|6 | user1 has bound the device, shared it with user2, revoked user2's permission, and removed the device|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized remote control by user2
**Impact effect**: User2 can control the device remotely even after user1 has revoked the permission.

**Attack Path** :
1. Attackers accumulate knowledge through "user2|remote|DeviceControl" in state s3
2. Replay the "user2|remote|DeviceControl" action in state s4
3. Bypass the permission check to enter privilege state s4 where user2 can control the device remotely