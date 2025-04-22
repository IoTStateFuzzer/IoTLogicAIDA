

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state. No devices added, no users invited.
1 | Device added by user1. User1 has device control, can remove device or invite user2.
2 | Error/Inactive state. Most operations return NoElement.
3 | user2 is invited into home (after invitation acceptance). Both users have device control.
4 | Device added and user2 invited. Both users can control devices.
5 | user2 has successfully controlled the device locally, stored in KS. Both users retain control.
6 | Device removed by user1. user2's DeviceControl attempts fail but KS remains.
7 | user2 removed from home by user1, but user2 retains device control capability via KS.
8 | Device removed and user2 removed. user2 cannot control.
9 | Device re-added after removal. user2's control attempts partially fail.
10 | user2 invited again after device re-addition. Mixed control success.

# Critical Vulnerability report
## Vulnerability 1: Improper Access Revocation
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate device control actions
2. Replay DeviceControl action after being removed from home
3. Bypass permission revocation check to maintain unauthorized control

**Repeat steps** :
1. s0 → s1 via user1|local|AddDevice
2. s1 → s4 via user1|local|InviteAndAccept
3. s4 → s5 via user2|local|DeviceControl (stores attack capability)
4. s5 → s7 via user1|local|RemoveFromHome
5. s7 remains in s7 via repeated user2|local|DeviceControl

**Vulnerability Analysis**:
The system fails to invalidate attacker's session credentials after home removal. When user1 removes user2 via RemoveFromHome operation:
- BaseModel would transition to state s0 (full permission revocation)
- StateFuzzing incorrectly allows user2 to retain DeviceControl capability in state s7 through KS persistence

This violates integrity and confidentiality as attackers maintain device control after permission revocation, demonstrating failure to implement proper authorization checks on stored credentials.