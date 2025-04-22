# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. User1 can add devices or invite User2.
1 | Device added by User1. User1 can control the device, remove it, or invite User2.
2 | Error/Invalid state with no permissible operations.
3 | User1 has invited User2 to the home (QR generated). User2 can scan QR.
4 | User2 scanned QR (pending acceptance). User2 can accept the invitation.
5 | User2 accepted invite, gaining device control. User1 can manage device/invites.
6 | User1 re-invited User2. Both have control; User2 can quit home.
7 | User2 has control, User1 can remove device or re-invite. User2 can quit.
8 | User1 removed device after sharing. User1 can re-add; User2's access is revoked.
9 | User2 quit the home. User1 can re-invite or add devices.
10 | User1 added device after User2 scanned QR. User2 can accept invite.
11 | User1 invited User2 again. User2 can scan QR again.
12 | User1 removed device after User2 quit. User1 can re-add or re-invite.
13 | User1 added device after multiple invites. User2 can accept or scan.
14 | User1 re-invited User2 after device removal. User2 can scan/accept.
15 | User2 has active control (post-device re-addition). Both users can control devices.
16 | User1 removed device after User2 regained access. User2's control fails.
17 | User2 quit after device re-addition. User1 can add devices again.
18 | User1 re-added device post-User2 quit. User2 needs to re-scan QR.
19 | User2 quit home but retains KS for DeviceControl. **Unauthorized control possible**.
20 | User2 accepted invite after device reconfiguration. Valid control state.
21 | User2 scanned QR again after device changes. Valid control state.
22 | User1 invited User2 post-device removal. User2 can accept.
23 | User1 re-invited User2 after complex state transitions. Valid control.
24 | User2 accepted invite after multiple device operations. Valid control.
25 | User2 controls device after multiple state changes. Valid but risky if KS persists.
26 | User1 removed device post-User2 access. User2's control fails.
27 | User2 quit after device re-addition. User1 can re-invite.
28 | User1 re-added device post-User2 quit. User2 needs to re-scan.
29 | User2 controls device after re-invitation. Valid but KS retention risks.
30 | User2 retains KS and controls device post-reconfiguration. **Unauthorized control possible**.
31 | User2 quit after prolonged access. Control attempts fail.
32 | Complex state with User2 controlling after multiple invites. Potential KS misuse.

# Critical Vulnerability report
## Vulnerability 1: Post-Quit Device Control via Retained Knowledge Set
**Threat Level** : High Risk

**Attack Path** :
1. Attackers gain legitimate access via invitation and perform DeviceControl (updates KS).
2. User2 quits the home, transitioning to state s19/s30 where KS retains DeviceControl.
3. Attacker replays DeviceControl via API, bypassing revocation checks.

**Repeat steps** :
1. From s0: User1 adds device (s0→s1), invites User2 (s1→s3).
2. User2 scans QR (s3→s4), accepts invite (s4→s5→s6).
3. User2 performs DeviceControl via UI (s6→s7→s15; KS updated).
4. User2 quits home (s15→s19). 
5. In s19, User2 replays "user2|remote|DeviceControl" via API (KS available), successfully controlling the device despite revocation.