# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no invitations sent. User1 can add devices or invite user2.
1 | Device added by user1. User1 can control/remove the device or invite user2.
2 | Error/Invalid state. No operations available.
3 | Invitation initiated by user1 (QR generated). User2 can scan QR.
4 | QR scanned by user2. Awaiting acceptance.
5 | User2 accepted invitation but device not added. Partial access.
6 | Valid shared state: Both users have device control after complete invitation flow.
7 | User1 re-invited user2 while sharing exists. Both have control.
8 | Device removed after sharing. User2's access revoked.
9 | User2 quit family after device removal. System resetting.
10 | Device re-added after invitation. Complex shared state.
11 | Base device state with pending invitation.
12 | Device removed after complex sharing scenario.
13 | Multi-device shared state with active control.
14 | Secondary invitation state before QR scan.
15 | Active attack state: Attacker gained persistent control via replay.
16 | Device removed but attacker retains KS capability.
17 | Post-quit state with lingering attack potential.
18-32 | Various persistence states showing improper permission revocation and replay attack success.

# Critical Vulnerability report
## Vulnerability 1: Persistent Access After Permission Revocation
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through valid DeviceControl operations during legitimate access periods
2. Replay stored DeviceControl action after privilege revocation
3. Bypass authorization checks to maintain device control

**Repeat steps** :
1. From s0: user1 adds device -> s1
2. user1 invites -> s3
3. user2 scans QR -> s4
4. user2 accepts -> s5
5. user1 adds device again -> s8
6. user2 executes DeviceControl (stores in KS) -> s30
7. user2 quits home -> s31
8. Attacker replays DeviceControl in s31: Success

**Impact**: Allows attackers to maintain permanent device control after privilege revocation through state machine logic flaws, violating all CIA triad principles. The system fails to invalidate previous session credentials when users quit the family group.