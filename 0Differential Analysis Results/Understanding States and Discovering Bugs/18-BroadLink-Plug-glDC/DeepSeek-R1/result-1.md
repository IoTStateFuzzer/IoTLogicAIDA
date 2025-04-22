# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no users invited.
1 | Device added by user1. user1 has control.
2 | Invalid state; no operations possible.
3 | user1 has generated an invitation QR code for user2.
4 | user2 has scanned the invitation QR code but not yet accepted.
5 | user2 has accepted the invitation and is part of the home with device control permissions.
6 | user1 re-invited user2 after previous interactions. user2 has control.
7 | Device added by user1. user2 has active local device control permissions (via UI).
8 | Device added. user2 has remote device control and local control capability.
9 | user2 has quit the home. user1's device removed.
10 | user1 re-added device after invitation process. user2 has scanning capability.
11 | Device added post-invitation. user2 can scan QR.
12 | user2 quit after device operations. user1 retains control.
13 | user1 re-invited after device re-addition. user2 can accept.
14 | user1 invited user2 again. user2 can scan/accept.
15 | user2 actively controls device locally (permissions active).
16 | Device removed by user1. user2's control attempts fail.
17-32 | Extended states reflecting combinations of device additions/removals and user2's replay attempts with stored knowledge. Most represent scenarios where user2 retains KS but cannot effectively control devices post-revocation.

# Critical Vulnerability report
## Vulnerability 1: Information Leakage via Error Message Differentiation
**Threat Level** : High Risk

**Attack Path** :
1. Attackers gain temporary legitimate access to device control through normal invitation flow.
2. After permission revocation, attacker replays DeviceControl action via API.
3. System returns distinct error messages indicating whether the device existed previously.

**Repeat steps** :
1. From s0: user1|local|AddDevice → s1.
2. user1|local|InviteToHome → s3.
3. user2|remote|ScanQRCode → s4.
4. user2|remote|AcceptInvite → s5 (user2 has permissions).
5. user1|local|RemoveDevice → transitions to s16.
6. user2|local|DeviceControl (via API replay) → system returns "Operation failed, response is empty" (state remains s16). Compare with s0's "NoElement" response for same action.