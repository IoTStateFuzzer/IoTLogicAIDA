# State Semantic mapping table

|State | Semantic Description|
|-----|---------|
|0 | Initial state, no device bound, no permissions granted.|
|1 | User1 has bound the device (camera), user2 has no permissions.|
|2 | Error state, no operations are successful.|
|3 | User1 has bound the device and shared it with user2, awaiting user2's acceptance.|
|4 | User1 has bound the device and user2 has accepted the share, both have control permissions.|
|5 | User1 has removed the device, no permissions for user2.|
|6 | User1 has re-added the device, user2 has no permissions.|
|7 | User1 has re-added the device and shared it with user2, awaiting user2's acceptance.|
|8 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|
|9 | User1 has bound the device and user2 has accepted the share, both have control permissions.|
|10 | User1 has removed the device, no permissions for user2.|
|11 | User1 has re-added the device, user2 has no permissions.|
|12 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|
|13 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|
|14 | User1 has re-added the device and shared it with user2, awaiting user2's acceptance.|
|15 | User1 has removed the device, no permissions for user2.|
|16 | User1 has re-added the device, user2 has no permissions.|
|17 | User1 has re-added the device and shared it with user2, awaiting user2's acceptance.|
|18 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|
|19 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|
|20 | User1 has re-added the device, user2 has no permissions.|
|21 | User1 has re-added the device and shared it with user2, awaiting user2's acceptance.|
|22 | User1 has re-added the device and user2 has accepted the share, both have control permissions.|

# Base model report

Every thing is OK.

# Divergent model report

## Vulnerability 1: Unauthorized Device Control by User2
**Impact effect**: User2 can control the device even after User1 has revoked the sharing permissions.

**Attack Path** :
1. User1 shares the device with User2 and User2 accepts the share, entering state 4.
2. User1 revokes User2's permission by executing UnshareCamera, transitioning to state 1.
3. User2 attempts to control the device using API hooking in state 9, bypassing the permission check.
4. User2 successfully controls the device, entering privilege state 9.