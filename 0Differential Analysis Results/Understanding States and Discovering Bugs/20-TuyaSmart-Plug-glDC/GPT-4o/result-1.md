# State Semantic Mapping Table

|State | Semantic Description|
|------|----------------------|
|0 | Indicates the initial status|
|1 | user1 has added the device|
|2 | Error state, no actions can be performed|
|3 | user1 has added the device and shared it with user2|
|4 | user1 has added the device, shared it with user2, and user2 has controlled the device locally|
|5 | user1 has added the device, shared it with user2, user2 has controlled the device locally, and user1 has unshared the device|
|6 | user1 has added the device, shared it with user2, user2 has controlled the device locally, and user1 has removed the device|
|7 | user1 has added the device, shared it with user2, user1 has removed the device, and added the device again|
|8 | user1 has added the device, shared it with user2, user1 has removed the device, added the device again, and shared it with user2 again|

# Base Model Report

Everything is OK.

# Divergent Model Report

## Vulnerability 1: Unauthorized Device Control by user2
**Impact effect**: user2 can control the device even after user1 has unshared the device.

**Attack Path**:
1. Attackers accumulate knowledge through user2|local|DeviceControl in state s3.
2. Replay the user2|local|DeviceControl action in state s4.
3. Bypass the unshare check to enter privilege state s4, where user2 can still control the device.