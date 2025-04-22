# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. User1 can add a device, invite users, or attempt device control (which fails). User2 has no permissions.
1 | Device added by User1. User1 has full control, can remove device or invite User2. User2 has no access.
2 | Universal failure/error state. All operations return NoElement.
3 | Invitation initiated by User1 (no device context). User2 can scan QR code to proceed.
4 | QR code scanned by User2 (pre-acceptance state). User2 can accept invitation.
5 | User2 accepted invitation but device not configured. Limited actions available.
6 | User2 in family with device access. Both users can control devices.
7 | User2 has active device control permissions. Attacker can click UI to execute "DeviceControl".
8 | User2 with device control in shared context. Re-invitation possible.
9 | User2 quit home but residual state exists. Requires cleanup.
10 | Device reconfiguration state after User2 acceptance. Contains mixed permissions.
11 | Device bound state with active invitation process. User2 can scan QR code.
12 | Post-quit state with device removed. Requires device reconfiguration.
13 | Active device with pending invitations. Complex permission state.
14 | Invitation loop state with multiple QR scans. Contains race condition potential.
15 | User2 has UI-clickable device control (legitimate access). KS updated with this capability.
16 | Device removed by User1 but attacker retains KS entry. Critical security boundary state.
17 | Post-quit state with stale device references. Potential info leakage vector.
18 | Reconfigured device state with partial permissions. Requires validation.
19 | Orphaned device control state. Should not exist in normal flow.
20 | Multi-invitation conflict state. Contains permission escalation risks.
21 | Invalid QR scan state with error handling issues.
22 | Failed invitation state with residual permissions.
23 | Duplicate device control permissions state.
24 | Race condition state during device re-addition.
25 | Stale invitation acceptance state.
26 | Post-removal attack state with API replay potential.
27 | Cleanup failure state. Retains residual API access.
28 | Boundary state for permission validation checks.
29 | Privilege conflict state between local/remote control.
30 | Active attack state - User2 maintains control after KS update.
31 | CRITICAL VULNERABILITY STATE: User2 retains device control after quitting home.
32 | Final privilege escalation state through API replay.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Home Quitting
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate device control actions
2. Replay device control action after quitting home
3. Bypass permission revocation check to maintain unauthorized control

**Repeat steps** :
1. From s0: user1|local|AddDevice -> s1
2. user1|local|InviteToHome -> s11
3. user2|remote|ScanQRCode -> s10
4. user2|remote|AcceptInvite -> s8
5. user2|local|DeviceControl (UI click) -> s30 (updates KS)
6. user2|remote|QuitHome -> s31
7. In s31: user2|local|DeviceControl (API replay) successfully executes

**Impact** : 
User2 maintains persistent device control capabilities after officially leaving the home, violating all CIA triad principles:
- Confidentiality: Accesses device status without authorization
- Integrity: Executes unauthorized control commands
- Availability: Maintains access despite permission revocation

**Root Cause** :
State transition s30->s31 through QuitHome action fails to clear KS entries and doesn't invalidate existing device control credentials. The system maintains UDP control channels without re-authentication after permission changes.