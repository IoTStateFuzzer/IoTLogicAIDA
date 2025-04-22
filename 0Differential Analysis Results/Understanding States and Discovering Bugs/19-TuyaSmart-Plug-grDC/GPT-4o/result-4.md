# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state |
| 1     | Device added by user1, user2 has no control permissions |
| 2     | Error state, no actions are executable |
| 3     | Device shared with user2, both user1 and user2 have control permissions |
| 4     | Device shared with user2, user2 has executed remote control, both user1 and user2 have control permissions |
| 5     | Device shared with user2, user2's permission revoked, user2 has knowledge for remote control |
| 6     | Device removed by user1, user2's permission revoked, user2 has knowledge for remote control |

# Base Model Report

Every thing is OK.

# Divergent Model Report

## Vulnerability 1: Unauthorized Device Control by User2
**Impact effect**: User2 can control the device remotely even after their permission has been revoked by user1.

**Attack Path**:
1. Attackers accumulate knowledge through user2|remote|DeviceControl in state 3.
2. Replay the user2|remote|DeviceControl action in state 4.
3. Bypass the permission check to enter privilege state 4, where user2 can control the device remotely.

## Vulnerability 2: Unauthorized Device Control by User2 after Device Removal
**Impact effect**: User2 can attempt to control the device remotely even after the device has been removed by user1.

**Attack Path**:
1. Attackers accumulate knowledge through user2|remote|DeviceControl in state 3.
2. Replay the user2|remote|DeviceControl action in state 6.
3. Bypass the permission check to enter privilege state 6, where user2 can attempt to control the device remotely.