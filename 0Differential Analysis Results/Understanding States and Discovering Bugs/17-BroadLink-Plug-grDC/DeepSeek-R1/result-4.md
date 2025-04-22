# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. user1 can add devices or invite user2.
1 | user1 has added a device. user1 can control, remove, or invite user2.
2 | Error/Invalid state with no operational capabilities.
3 | user1 has initiated an invitation (QR generated). user2 can scan QR.
4 | user2 has scanned the invitation QR (pending acceptance).
5 | user2 accepted invitation: user2 has temporary home access with device control.
6 | user1 re-invited user2 while user2 is already in home (duplicate invite).
7 | Both users have device control. user2 can legally control devices via UI.
8 | Device added post-acceptance. Both users have control.
9 | user2 quit home. user1's device removed.
10 | Device added after invitation scan. user2 can accept invite.
11 | Device added post-invitation. user2 can scan QR.
12 | user2 quit home after device operations. user1 can reinvite.
13 | user1 invited again post-device operations. user2 can accept.
14 | user1 initiated new invite after previous operations. user2 can scan.
15 | Active state where user2 has DeviceControl in KS (can replay).
16 | user1 removed device after attack. user2's DeviceControl now fails.
17 | user2 quit home after device removal. user1 can add devices.
18 | user1 added device post-quit. user2 needs rebind (no access).
19 | user2 retains KS access post-quit (critical vulnerability state).
20 | user1 reinvited post-attack. user2 can accept again.
21 | user2 scanned QR in semi-authorized state.
22 | user2 accepted invite post-device removal.
23 | user1 invited after complex state transitions.
24 | user2 needs rebind after new device addition.
25 | user2 has active control via KS post-reinvite.
26 | user2 in limbo state after device removal and invite.
27 | Final quit state with no device access.
28 | user2's DeviceControl blocked post-quit.
29 | Complex replay state with mixed permissions.
30 | Persistent KS access state with valid control.
31 | user2 retains control post-quit (info leakage).
32 | Final persistent attack state with device control.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Quitting Home
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge by legally obtaining DeviceControl permission via invitation.
2. After being removed via QuitHome, attacker replays DeviceControl action via API using stored KS.
3. Bypass permission revocation checks to maintain control in post-quit states.

**Repeat steps** :
1. From s0: user1 adds device → s1.
2. user1 invites user2 → s3.
3. user2 scans QR → s4, accepts invite → s5.
4. user1 adds device → s8. user2 controls device → s30 (KS updated).
5. user2 quits home → s31. Despite revocation, user2 replays DeviceControl → remains in s31 with successful control.

**Impact**: Attacker maintains device control after permission revocation, violating integrity and access control principles.