

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state. User1 can add a device (transition to s1), invite+accept user2 (s3), but device control attempts fail.
1 | Device added state. User1 can remove device (back to s0), invite user2 (s4), and control device locally/remotely.
2 | Dead-end state. All operations loop back with NoElement responses.
3 | User2 invited+accepted state (no device). User1 can add device (s4) or remove user2 (s0).
4 | Device added + user2 invited state. User2 can legally control device via UI (Clickable).
5 | Active shared control state. Both users maintain device control permissions.
6 | Device removed state after sharing. User2's control attempts now fail (error 404).
7 | User2 removed from home state. User2's control attempts show unauthorized (error 401).
8 | Empty home state after user removal. Requires device re-addition.
9 | Device re-added after home cleanup. User2 access remains revoked.
10 | New device added post-cleanup. User2 regains access through home membership.

# Critical Vulnerability report
## Vulnerability 1: Post-Removal Access Through Home Membership
**Threat Level** : Medium Risk

**Attack Path** :
1. Attacker maintains home membership after device removal
2. Legitimate device re-addition revives attacker access
3. Bypasses explicit device-sharing requirements

**Repeat steps** :
1. From s0: user1|local|AddDevice → s1
2. user1|local|InviteAndAccept → s4
3. user2|remote|DeviceControl → s5
4. user1|local|RemoveDevice → s6
5. user1|local|AddDevice → s10
6. user2|remote|DeviceControl → s5 (regains control)

**Analysis**:
While technically compliant with home membership rules, this exposes a design flaw where:
1. Home membership grants blanket device access
2. No re-verification occurs when devices are removed/re-added
3. Creates persistent access through membership without explicit re-sharing

Recommended mitigation: Implement device-level authorization checks independent of home membership status.