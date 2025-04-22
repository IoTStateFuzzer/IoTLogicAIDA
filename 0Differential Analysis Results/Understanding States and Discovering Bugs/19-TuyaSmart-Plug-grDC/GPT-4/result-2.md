# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | Error state where no operations can be executed|
|3 | User1 has shared the plug with user2, both have control permissions|
|4 | User2 has knowledge of remote device control and can click UI; both users have control permissions|
|5 | User2 has knowledge of remote device control but cannot click UI; user1 has revoked user2's permission but user2 still knows about the device|
|6 | User2 has knowledge of remote device control but cannot click UI; user1 has unbound the device, revoking all permissions|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Information Leakage and Unauthorized Control
**Impact effect**: User2 retains knowledge about the device and can attempt unauthorized control even after permissions are revoked.

**Attack Path** :
1. User2 accumulates knowledge through successful remote device control in state s3.
2. User1 revokes user2's permission by unsharing the plug, transitioning from s4 to s5.
3. Despite the revocation, user2 still has knowledge and attempts remote control in s5, although the operation fails, the attempt itself should not be possible.
4. User2 retains the ability to attempt remote control in s6 after the device is removed by user1, indicating persistent knowledge and potential for unauthorized actions.