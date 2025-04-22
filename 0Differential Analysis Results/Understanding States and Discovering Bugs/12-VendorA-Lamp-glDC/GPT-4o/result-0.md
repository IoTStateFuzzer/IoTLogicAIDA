# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | Indicates the state after user1 adds a device|
|2 | Indicates an error state where no operations are possible|
|3 | Indicates the state after user1 invites user2 and user2 accepts the invitation|
|4 | Indicates the state where user2 has control permissions|
|5 | Indicates the state where user2 has control permissions and has performed local device control|
|6 | Indicates the state where user2 has control permissions, but user1 has removed the device|
|7 | Indicates the state where user2 has control permissions, but user1 has removed user2 from the home|
|8 | Indicates the state where user2 has control permissions, but user1 has removed the device and user2 has attempted local control|
|9 | Indicates the state where user2 has control permissions, but user1 has removed the device and user2 has attempted local control and user1 has invited user2 again|
|10 | Indicates the state where user2 has control permissions and user1 has added the device again|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Device Control
**Impact effect**: User2 can control the device even after being removed from the home by user1.

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl in state 4
2. Replay the user2|local|DeviceControl action in state 7
3. Bypass the removal check to enter privilege state 5

## Vulnerability 2: Unauthorized Device Control After Removal
**Impact effect**: User2 can control the device even after user1 removes the device.

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl in state 4
2. Replay the user2|local|DeviceControl action in state 6
3. Bypass the device removal check to enter privilege state 5