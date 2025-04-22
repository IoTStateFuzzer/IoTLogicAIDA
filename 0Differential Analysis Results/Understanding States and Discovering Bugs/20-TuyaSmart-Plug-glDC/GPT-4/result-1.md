# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | Error state where no operations are executable|
|3 | User1 has shared the plug with user2, and user2 has access to control the device|
|4 | User2 has knowledge of local device control and can execute it; User1 has shared the plug with user2, and user2 has access to control the device|
|5 | User2 has knowledge of local device control but cannot execute it; User1 has shared the plug with user2, and user2 has access to control the device|
|6 | User2 has knowledge of local device control but cannot execute it; User1 has unshared the plug, revoking user2's access|
|7 | User1 has bound the device (plug) again after unsharing; User2 has knowledge of local device control but cannot execute it|
|8 | User1 has shared the plug with user2 again, and user2 has access to control the device; User2 has knowledge of local device control and can execute it|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Control and Knowledge Retention
**Impact effect**: User2 retains knowledge and control capabilities even after permissions are revoked, potentially leading to unauthorized control and privacy breaches.

**Attack Path** :
1. Attackers accumulate knowledge through "user2|local|DeviceControl" in state s3.
2. Replay the "user2|local|DeviceControl" action in state s4, s5, and s8.
3. Bypass the permission check to enter privileged state s4 and s8, where user2 can control the device despite the revocation of permissions in previous states.

This vulnerability allows the attacker (user2) to retain control and knowledge of the device operations even after the device owner (user1) has explicitly revoked such permissions. This can lead to unauthorized device control and potential privacy breaches, as user2 should not have any control or knowledge about the device once their permissions are revoked.