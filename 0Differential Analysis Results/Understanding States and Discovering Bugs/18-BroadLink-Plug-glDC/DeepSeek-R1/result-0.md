# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. User1 can add devices or invite User2.
1 | User1 has added a device. User1 can control or invite User2.
2 | Error/Invalid state with no operational capabilities.
3 | User1 has initiated an invitation (QR generated). User2 can scan QR.
4 | User2 has scanned QR but not accepted. User2 can accept invite.
5 | User2 accepted invite but hasn't been granted full permissions yet.
6 | User2 is part of the home with device control permissions.
7 | User2 has active device control permissions (local/remote).
8 | Similar to s6 but with additional invitation capabilities.
9 | User2 quit home; permissions revoked but invitation possible.
10 | Post-device addition after QR scan state.
11 | User1 has device, User2's permissions revoked.
12 | Post-device removal state with lingering invite capabilities.
13 | Active device with User2 invitation pending.
14 | Device added post-invitation scan state.
15 | User2 retains local device control after critical operations.
16 | Device removed but User2 attempts local control (fails).
17 | Post-quit state with no permissions but QR re-scan possible.
18 | Device re-added after quit; User2 can control locally.
19 | **Vulnerable state**: User2 retains local control after quitting home.
20-32 | Extended states with complex permission/invitation flows, some retaining improper User2 access.

# Critical Vulnerability report
## Vulnerability 1: Post-Quit Local Device Control Retention
**Threat Level** : High Risk

**Attack Path** :
1. Attackers gain legitimate device control permissions through invitation acceptance.
2. After quitting the home family (supposed to revoke permissions), attackers exploit retained local control capabilities.
3. Bypass permission revocation checks to maintain persistent device control.

**Repeat steps** :
1. From s0: User1 adds device → s1 → invites User2 → s3.
2. User2 scans QR (s3→s4) → accepts invite (s4→s5).
3. Reach s7 where User2 has control. User2 quits home (s7→s11).
4. **Statefuzzing divergence**: In some paths (e.g., s15→s19 via quit action), User2 retains local control capability.
5. In s19, User2 replays "user2|local|DeviceControl" via stored KS entry → maintains unauthorized control.

**Impact**: Attacker maintains device control after permission revocation, violating integrity/confidentiality.