# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. User1 can add a device; User2 has no permissions.
1 | Device added by User1. User1 has full control; User2 has no access.
2 | Invalid state (transitions loop back). Indicates operations attempted without proper prerequisites.
3 | Camera shared by User1. User2 can accept the share.
4 | User2 accepted camera share. Both users have control permissions.
5 | Device removed after sharing. User2's share attempts fail.
6 | Device re-added after removal. Similar to state1 but in a new context.
7 | Camera shared again after re-adding. User2 can accept.
8 | User2 accepted re-shared camera. Both control permissions active.
9 | User2 exploited control post-removal? Possible invalid persistence.
10 | Device removed again. User2's control attempts fail.
11 | Device added again after multiple cycles.
12 | Camera unshared by User1 but User2 retains control (vulnerable state).
13 | Camera shared again in a complex context.
14 | Another sharing cycle with User2 access.
15 | Device removed in multi-share context.
16 | Device re-added in multi-context.
17 | Camera shared again with vulnerable acceptance path.
18 | User2 in persistent control despite unsharing.
19 | Critical vulnerability state: User2 retains control after unshare.
20 | Partial cleanup but User2 still has access.
21 | Multi-layer sharing failure with lingering access.
22 | Complex state with mixed permissions.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Unsharing
**Threat Level** : High Risk

**Attack Path** :
1. Attackers gain temporary legitimate access through accepted sharing.
2. After the owner (User1) revokes sharing via UnshareCamera, attacker retains device control capabilities.
3. Bypasses permission revocation checks, maintaining unauthorized access.

**Repeat steps** :
1. From s0: User1 adds device (s0→s1).
2. User1 shares camera (s1→s3).
3. User2 accepts share (s3→s4).
4. User2 performs DeviceControl (s4→s9).
5. User1 unshares camera (s9→s12 via UnshareCamera).
6. In s12, User2 successfully executes DeviceControl again (s12→s12), demonstrating retained access despite revocation.