# State Semantic mapping table

|State | Semantic Description|
|-----|----------------------|
|s0 | Initial state where no device is bound, and no actions have been taken.|
|s1 | Device is bound by user1. User1 has control over the device.|
|s2 | Error state where no operations are successful.|
|s3 | Device is bound by user1 and shared with user2, awaiting user2's acceptance.|
|s4 | Device is bound by user1 and shared with user2. Both users have control over the device.|
|s5 | Device is unbound by user1. No users have control.|
|s6 | Device is re-bound by user1. User1 has control.|
|s7 | Device is re-bound by user1 and shared with user2, awaiting user2's acceptance.|
|s8 | Device is re-bound by user1 and shared with user2. Both users have control.|
|s9 | Device is bound by user1 and shared with user2. User2 has control over the device.|
|s10 | Device is unbound by user1. No users have control.|
|s11 | Device is re-bound by user1. User1 has control.|
|s12 | Device is bound by user1 and shared with user2. User2 has control over the device.|
|s13 | Device is bound by user1 and shared with user2. User2 has control over the device.|
|s14 | Device is re-bound by user1 and shared with user2, awaiting user2's acceptance.|
|s15 | Device is unbound by user1. No users have control.|
|s16 | Device is re-bound by user1. User1 has control.|
|s17 | Device is re-bound by user1 and shared with user2, awaiting user2's acceptance.|
|s18 | Device is re-bound by user1 and shared with user2. User2 has control over the device.|
|s19 | Device is bound by user1 and shared with user2. User2 has control over the device.|
|s20 | Device is re-bound by user1. User1 has control.|
|s21 | Device is re-bound by user1 and shared with user2. User2 has control over the device.|
|s22 | Device is re-bound by user1 and shared with user2. User2 has control over the device.|

# Base model report

Every thing is OK.

# Divergent model report

## Vulnerability 1: Unauthorized Device Control by User2
**Impact effect**: User2 can control the device even after user1 has unshared or removed the device, which should not be possible.

**Attack Path** :
1. User1 shares the device with user2, and user2 accepts the share, gaining control.
2. User1 unshares or removes the device, expecting user2 to lose control.
3. User2 replays the "DeviceControl" action in states like s9, s12, s13, s18, s19, s21, and s22.
4. User2 successfully controls the device despite user1's actions to revoke access.