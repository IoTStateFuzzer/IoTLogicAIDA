# State Semantic mapping table

|State | Semantic Description|
|-----|---------|
|0 | Initial state where no device is bound. Neither user1 nor user2 has control permissions.|
|1 | State where user1 has bound the camera device. User1 has control permissions, user2 does not.|
|2 | Error state where no operations are successful. Neither user1 nor user2 has control permissions.|
|3 | State where user1 has shared the camera with user2, but user2 has not yet accepted the share. User1 has control permissions, user2 does not.|
|4 | State where user2 has accepted the camera share. Both user1 and user2 have control permissions.|
|5 | State after user1 removes the device. Neither user1 nor user2 has control permissions.|
|6 | State where user1 re-adds the camera device after removal. User1 has control permissions, user2 does not.|
|7 | State where user1 re-shares the camera with user2 after re-adding the device. User1 has control permissions, user2 does not.|
|8 | State where user2 has accepted the re-share. Both user1 and user2 have control permissions.|
|9 | State where user2 has control permissions through API hooking. User1 also has control permissions.|
|10 | State after user1 removes the device while user2 has control permissions through API hooking. Neither user1 nor user2 has control permissions.|
|11 | State where user1 re-adds the camera device after removal. User1 has control permissions, user2 does not.|
|12 | State where user1 unshares the camera from user2. User1 has control permissions, user2 does not.|
|13 | State where user1 re-shares the camera with user2 after unsharing. User1 has control permissions, user2 does not.|
|14 | State where user2 has accepted the re-share. Both user1 and user2 have control permissions.|
|15 | State after user1 removes the device while user2 has control permissions through API hooking. Neither user1 nor user2 has control permissions.|
|16 | State where user1 re-adds the camera device after removal. User1 has control permissions, user2 does not.|
|17 | State where user1 re-shares the camera with user2 after re-adding the device. User1 has control permissions, user2 does not.|
|18 | State where user2 has accepted the re-share. Both user1 and user2 have control permissions.|
|19 | State where user2 has control permissions through API hooking. User1 also has control permissions.|
|20 | State where user1 unshares the camera from user2. User1 has control permissions, user2 does not.|
|21 | State where user1 re-shares the camera with user2 after unsharing. User1 has control permissions, user2 does not.|
|22 | State where user2 has accepted the re-share. Both user1 and user2 have control permissions.|

# Base model report

Every thing is OK.

# Divergent model report

## Vulnerability 1: Unauthorized Device Control by User2
**Impact effect**: User2 can control the camera device without proper authorization, potentially accessing video streams and device information.

**Attack Path** :
1. User1 shares the camera with user2, and user2 accepts the share legally.
2. User1 unshares the camera from user2, revoking user2's control permissions.
3. User2 attempts to control the device using API hooking in state 4, successfully bypassing the unshare action and gaining control permissions again.
4. User2 maintains control permissions through subsequent states (e.g., state 9, state 19) despite user1's attempts to revoke access.