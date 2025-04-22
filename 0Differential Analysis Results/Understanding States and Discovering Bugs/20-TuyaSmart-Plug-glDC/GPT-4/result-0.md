# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Indicates the initial status|
|1 | User1 has bound the device, no sharing yet|
|2 | Error state or no device bound|
|3 | User1 has shared the device with User2, and User2 has control permissions|
|4 | User2 has control permissions and knowledge for local device control|
|5 | User1 has unshared the device, but User2 retains knowledge for local device control|
|6 | User1 has removed the device, User2 retains knowledge but no control permissions|
|7 | User1 has re-added the device, User2 retains knowledge but no control permissions|
|8 | User1 has re-shared the device with User2, both have control permissions, and User2 retains knowledge|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Unauthorized Control Retention
**Impact effect**: User2 retains control and knowledge of the device even after User1 has unshared the device.

**Attack Path** :
1. User1 shares the device with User2, moving from state s1 to s3.
2. User2 controls the device locally in state s3, gaining knowledge and transitioning to state s4.
3. User1 unshares the device with User2, intending to revoke control, but User2 transitions to state s5 retaining control knowledge.
4. User2 still can control the device locally in state s5, indicating unauthorized retention of control capabilities.

This vulnerability allows User2 to maintain control over the device despite User1's explicit action to revoke such permissions, posing a significant security risk.