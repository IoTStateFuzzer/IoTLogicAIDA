

# State Semantic mapping table for statefuzzing
State | semantic description
-----|---------
0 | Initial state: No devices added, no users invited.
1 | Device added by user1. User2 not invited yet.
2 | Error/Invalid state (all operations lead back to s2).
3 | User2 invited and added to home (no device present).
4 | Device added and user2 part of home. Both users can control the device.
5 | user2 has performed device control (attacker's KS contains DeviceControl). Valid device control state.
6 | Device removed by user1. User2 still in home but device not present.
7 | User2 removed from home by user1. However, user2 retains device control capability via KS.
8 | Device removed and user2 removed. Empty state similar to s2.
9 | Device re-added after removal. User2 not in home but KS persists.
10 | Device re-added with user2 still in home (via prior invite). Valid control state.

# Critical Vulnerability report
## Vulnerability 1: Privilege Retention After User Removal
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate device control actions during authorized access
2. Replay the "user2|local|DeviceControl" action in state s7 (post-removal state)
3. Bypass authorization checks to maintain device control capabilities after removal

**Repeat steps** :
1. s0 → user1|local|AddDevice → s1
2. s1 → user1|local|InviteAndAccept → s4
3. s4 → user2|local|DeviceControl → s5 (attacker gains KS)
4. s5 → user1|local|RemoveFromHome → s7
5. s7 → user2|local|DeviceControl (via API replay) → remains in s7 with successful control

**Impact**: Attacker maintains persistent device control capabilities after being removed from home system, violating authorization mechanisms and integrity of access controls.