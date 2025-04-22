# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device|
|2 | User1 has unbound the device|
|3 | User1 has bound the device and invited User2, User2 has accepted the invitation|
|4 | User1 has unbound the device and invited User2, User2 has accepted the invitation|
|5 | User1 has bound the device and invited User2, User2 has accepted the invitation and has control over the device|
|6 | User1 has unbound the device and User2 has lost control over the device|
|7 | User1 has removed User2 from the home, but User2 still has control over the device|
|8 | User1 has unbound the device and removed User2 from the home|
|9 | User1 has bound the device and removed User2 from the home|
|10 | User1 has bound the device, invited User2, User2 has accepted the invitation and has control over the device|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized control over the device
**Impact effect**: User2 can control the device even after being removed from the home by User1.

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl in state 5
2. Replay the user2|local|DeviceControl action in state 7
3. Bypass the user1|local|RemoveFromHome check to enter privilege state 7
