# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no invitations sent. user1 can add devices or invite user2.
1 | user1 has added a device. user1 can control/remove the device. No active invitations.
2 | Error/Invalid state (transitions loop back to s2). No valid operations here.
3 | user1 has invited user2 (QR generated). user2 can scan QR.
4 | user2 scanned QR (pending acceptance). user2 can accept invite.
5 | user2 accepted invite, part of the family. Both users have device control.
6 | user1 re-invited user2 (new QR). user2 can scan again.
7 | user2 in family with device control (post re-invite). Both can control devices.
8 | user1 added another device after initial setup. Both have expanded control.
9 | user2 quit family after being added. user1 can reinvite.
10 | Device added after invitation process. Mixed state with pending actions.
11 | Device removed after invitation. State with revoked permissions.
12 | user2 quit after multi-device setup. Clean revocation state.
13 | Complex invitation chain with multiple devices. Both users active.
14 | Post-quit state with partial device access. Mixed permissions.
15 | Attacker (user2) has KS:"DeviceControl" - can replay control commands via API.
16-32 | Various attack persistence states where user2 retains KS:DeviceControl after permission revocation, enabling replay attacks even after formal removal from the system.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control via Replay Attack
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate DeviceControl operations during temporary membership
2. Replay the "user2|remote|DeviceControl" action in states s15/s30 after being removed from the family
3. Bypass the permission revocation check to execute unauthorized device commands

**Repeat steps** :
1. From s0: user1 adds device ➔ s1
2. user1 invites user2 ➔ s3
3. user2 scans QR ➔ s4 ➔ accepts invite ➔ s5 (now has valid control rights)
4. user2 performs DeviceControl (added to KS)
5. user2 quits family ➔ s9/s11
6. Attacker replays "user2|remote|DeviceControl" via API in s15/s30 (using KS)
7. System accepts command despite revoked permissions (statefuzzing allows transition to s15/s30 with operational success response)

This violates CIA triad by allowing:
- Integrity violation (unauthorized device control)
- Confidentiality breach (device status leakage in error responses)
- Availability risk (malicious device manipulation)