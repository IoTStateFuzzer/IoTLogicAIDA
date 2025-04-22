# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. User1 can add devices or invite User2.
1 | Device added by User1. User1 can control, remove the device, or invite User2.
2 | Error or invalid state with no permissible actions.
3 | User1 has invited User2 (QR generated), but User2 hasn't scanned yet.
4 | User2 scanned the QR code (invitation pending acceptance).
5 | User2 accepted the invitation, gaining device control permissions.
6 | User1 re-invited User2 after previous interactions.
7 | User2 has active device control permissions via UI interaction.
8 | Device added again after removal; User2 retains legacy control permissions (VULNERABLE STATE).
9 | User2 quit the family, revoking permissions.
10 | Intermediate state after device re-addition.
11 | User1 invited User2 after initial device setup.
12 | State after User2 quits and User1 re-adds devices.
13 | User1 re-invited User2 post-device removal.
14 | Complex state with multiple invite/remove cycles.
15-32 | Extended states showing retained attacker capabilities via knowledge set (KS) exploitation paths.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Device Re-Addition
**Threat Level** : High Risk

**Attack Path** :
1. Attacker (User2) gains device control permissions via normal invitation flow.
2. User1 removes the device, revoking permissions temporarily.
3. User1 re-adds the device, but the system fails to reset permissions.
4. Attacker retains device control via legacy permissions without re-invitation.

**Repeat steps** :
1. From s0: User1 adds device ➔ s1.
2. User1 invites User2 ➔ s11.
3. User2 scans QR ➔ s10 ➔ accepts invite ➔ s8.
4. User1 removes device ➔ s5.
5. User1 re-adds device ➔ s8.
6. In s8: User2 executes `user2|local|DeviceControl` ➔ s30 (SUCCESSFUL CONTROL).

**Impact**: Attacker maintains unauthorized device control after device lifecycle reset, violating CIA triad by bypassing permission revocation mechanisms.