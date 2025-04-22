# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. User1 can add a device locally. User2 has no permissions.
1 | Device added by User1. User1 has full control and sharing capabilities. User2 has no access.
2 | Error/Invalid state for most operations (persistent NoElement responses).
3 | Camera shared by User1 (pending acceptance). User1 maintains control. User2 can accept sharing.
4 | User2 accepted camera sharing. Both users have device control permissions.
5 | Device removed after being shared. User2's access attempts fail due to invalid invitation.
6 | Device re-added by User1 after removal. Similar to s1 with fresh permissions.
7 | Camera re-shared by User1 after re-addition. User2 can accept again.
8 | User2 accepted re-shared camera. Both have control until revocation.
9 | First privileged attack state: User2 maintains control after device modifications.
10 | Device removed from attack state s9. User2's control attempts now fail.
11 | Device re-added after s10. User1 has control, User2's access blocked.
12 | Camera unshared from s9. User2 retains illegal control capability (vulnerability state).
13 | Camera re-shared from s12. User2 regains legitimate access.
14 | Camera shared from s11. Shows mixed permission states between users.
15 | Device removed from advanced attack states. User2 access revoked.
16 | Device re-added after s15. Clean permission state.
17 | Camera shared from s16. User2 can accept again.
18 | User2 accepted share from s17. Normal permission state.
19 | Privileged persistence state: User2 maintains control after multiple revocation attempts.
20 | Camera unshared from s19. User2 retains illegal access (critical vulnerability).
21 | Camera re-shared from s20. Permission state reset.
22 | Special transition state showing incomplete permission revocation.

# Critical Vulnerability report
## Vulnerability 1: Persistent Access After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attackers accumulate valid device control permission through normal sharing process
2. Replay device control action after privilege revocation in state s12/s20
3. Bypass permission revocation check to maintain unauthorized access

**Repeat Steps**:
1. s0 → s1 (User1 adds device)
2. s1 → s3 (User1 shares camera)
3. s3 → s4 (User2 accepts share)
4. s4 → s9 (User2 establishes control)
5. s9 → s12 (User1 unshares camera)
6. s12 remains vulnerable to User2's device control:
   - In state s12, User2|remote|DeviceControl → s12 (Success)

This violates the CIA triad through:
1. **Integrity**: Unauthorized control persists after revocation
2. **Confidentiality**: Attacker maintains access to device data streams
3. **Availability**: Legacy permissions affect normal access control

## Vulnerability 2: Cross-State Permission Inheritance
**Threat Level**: Medium Risk

**Attack Path**:
1. Attacker enters privileged state s19 through multiple share/revoke cycles
2. Maintains device control capabilities through state transitions
3. Inherits permissions across device removal/re-add operations

**Repeat Steps**:
1. Reach s19 through: s0→s1→s3→s4→s9→s19 (via multiple control operations)
2. s19 → s15 (User1 removes device)
3. s15 → s16 (User1 re-adds device)
4. Attacker in s16 can still attempt control using legacy knowledge

This demonstrates improper session invalidation and creates potential for:
- Zombie access through API replay attacks
- Privilege escalation across device lifecycles
- Hidden permission persistence not visible through UI