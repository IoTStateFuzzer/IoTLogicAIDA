# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device|
|2 | User1 has unbound the device|
|3 | User1 has invited User2 and User2 has accepted the invitation|
|4 | User1 has removed User2 from the home|
|5 | User2 has control over the device locally|
|6 | User1 has unbound the device and User2 has lost control over the device|
|7 | User1 has removed User2 from the home but User2 still has control over the device locally|
|8 | User1 has unbound the device and User2 has lost control over the device|
|9 | User1 has bound the device and User2 has lost control over the device|
|10 | User1 has invited User2 and User2 has accepted the invitation and User2 has control over the device locally|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Control
**Impact effect**: User2 can control the device locally even after being removed from the home by User1.

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl action in state 5
2. Replay the user2|local|DeviceControl action in state 7
3. Bypass the user1|local|RemoveFromHome check to enter privilege state 7
