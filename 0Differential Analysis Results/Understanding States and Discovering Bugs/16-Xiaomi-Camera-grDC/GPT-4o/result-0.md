# State Semantic Mapping Table
|State | Semantic Description|
|------|---------------------|
|0 | Initial state |
|1 | Device added by user1 |
|2 | Error state |
|3 | Device shared by user1, user2 needs to accept |
|4 | User2 accepted the device share |
|5 | Device removed by user1 |
|6 | Device re-added by user1 |
|7 | Device re-shared by user1 |
|8 | User2 re-accepted the device share |
|9 | User2 controlling the device after accepting share |
|10 | Device removed by user1 after user2 controlled it |
|11 | Device re-added by user1 after user2 controlled it |
|12 | Device unshared by user1 after user2 controlled it |
|13 | Device re-shared by user1 after user2 controlled it |
|14 | User2 re-accepted the device share after user1 re-shared it |
|15 | Device removed by user1 after user2 re-accepted the share |
|16 | Device re-added by user1 after user2 re-accepted the share |
|17 | Device re-shared by user1 after user2 re-accepted the share |
|18 | User2 re-accepted the device share after user1 re-shared it |
|19 | User2 controlling the device after re-accepting share |
|20 | Device unshared by user1 after user2 re-accepted the share |
|21 | Device re-shared by user1 after user2 controlled it |
|22 | User2 re-accepted the device share after user1 re-shared it |

# Base Model Report
Every thing is OK.

# Divergent Model Report
## Vulnerability 1: Unauthorized Device Control by User2
**Impact Effect**: User2 can control the device even after user1 has revoked the sharing permission.

**Attack Path**:
1. User1 shares the device with user2 (state 3).
2. User2 accepts the share and gains control (state 4).
3. User1 revokes the sharing permission (state 5).
4. User2 attempts to control the device using API hooking (state 9).
5. User2 successfully controls the device despite the revoked permission.

## Vulnerability 2: Information Leakage
**Impact Effect**: User2 can obtain device information even after the sharing permission has been revoked.

**Attack Path**:
1. User1 shares the device with user2 (state 3).
2. User2 accepts the share and gains control (state 4).
3. User1 revokes the sharing permission (state 5).
4. User2 attempts to control the device using API hooking (state 9).
5. User2 successfully retrieves device information despite the revoked permission.