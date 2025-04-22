# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | user1 has added the device|
|2 | Error state, no actions can be performed|
|3 | user1 has added the device and shared it with user2|
|4 | user1 has added the device, shared it with user2, and user2 has successfully controlled the device locally|
|5 | user1 has added the device, shared it with user2, user2 has successfully controlled the device locally, and user1 has revoked user2's permission|
|6 | user1 has added the device, shared it with user2, user2 has successfully controlled the device locally, user1 has revoked user2's permission, and user1 has removed the device|
|7 | user1 has added the device, shared it with user2, user2 has successfully controlled the device locally, user1 has revoked user2's permission, user1 has removed the device, and user1 has added the device again|
|8 | user1 has added the device, shared it with user2, user2 has successfully controlled the device locally, user1 has revoked user2's permission, user1 has removed the device, user1 has added the device again, and shared it with user2|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Device Control
**Impact effect**: The attacker (user2) can control the device even after user1 has revoked their permission.

**Attack Path** :
1. user1 adds the device (s0 -> s1)
2. user1 shares the device with user2 (s1 -> s3)
3. user2 controls the device locally (s3 -> s4)
4. user1 revokes user2's permission (s4 -> s5)
5. user2 replays the local control action (s5 -> s4)

In state s5, user2 should not be able to control the device as their permission has been revoked. However, they can still control the device by replaying the local control action, which is a security vulnerability.