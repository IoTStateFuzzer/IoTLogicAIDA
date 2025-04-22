# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device (plug)|
|2 | Error state where no operations can be executed|
|3 | User1 has shared the plug with user2, and user2 has access to control the device|
|4 | User2 has control over the device and has knowledge to perform local device control via API hooking|
|5 | User1 has unshared the plug, but user2 retains knowledge to perform local device control via API hooking|
|6 | User1 has removed the device, revoking all permissions from user2, but user2 retains knowledge to perform local device control via API hooking|
|7 | User1 has re-added the device after removal, shared it with user2, and user2 has access to control the device but failed to execute local control via API hooking|
|8 | User1 has re-shared the device with user2 after unsharing, and user2 has access to control the device and has knowledge to perform local device control via API hooking|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Retention of Control Knowledge
**Impact effect**: User2 retains knowledge to control the device even after their permissions have been revoked, which could potentially allow unauthorized actions if the knowledge is exploited.

**Attack Path** :
1. User2 accumulates knowledge through successful device control in state s3.
2. User1 revokes user2's permission by unsharing the plug, transitioning to state s5.
3. Despite the revocation, user2 retains the knowledge and attempts to control the device in state s5, indicating a security flaw where the knowledge should have been invalidated.

## Vulnerability 2: Unauthorized Control After Device Removal
**Impact effect**: User2 can attempt to control the device even after it has been removed by user1, indicating improper clearance of control capabilities and knowledge.

**Attack Path** :
1. User2 accumulates knowledge through successful device control in state s3.
2. User1 removes the device, transitioning to state s6.
3. User2 still retains the knowledge and attempts to control the device in state s6, showing that the removal of the device did not clear the stored knowledge, leading to potential unauthorized control attempts.