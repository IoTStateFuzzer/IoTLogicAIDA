# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no users invited.
1 | Device added by user1. User1 has control; user2 has no permissions.
2 | Invalid state (transient error state).
3 | Camera shared by user1 (invite pending). User2 can accept the share.
4 | User2 accepted camera share. Both users have control.
5 | Device removed by user1. All permissions revoked.
6 | Device re-added by user1 after removal. User1 has control.
7 | Camera re-shared by user1 (second invite pending).
8 | User2 accepted re-shared camera. Both have control.
9 | State after device removal from shared state. User2 retains KS for replay attempts.
10 | Device removed after complex sharing scenario. Clean state.
11 | Device re-added after multi-cycle removal. User1 in control.
12 | Camera unshared by user1 BUT user2 still has active control permissions (vulnerability state).
13 | Secondary camera share attempt failed due to existing permissions.
14 | Camera re-shared again after complex removal cycle.
15 | Final device removal state with KS residue.
16 | Device re-added after deep removal cycle.
17 | Failed reshare attempt in deep state.
18 | Successful reshare acceptance in deep state.
19 | Privilege escalation state - user2 retains control after revocation.
20 | Partial cleanup state with residual vulnerabilities.
21 | Failed reshare in advanced attack chain.
22 | Transient accepted share state with KS contamination.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Permission Revocation
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate access periods
2. Replay device control action in state s12/s19 after permission revocation
3. Bypass authorization check to maintain illegal control

**Repeat steps** :
1. s0 → s1 (user1 adds device)
2. s1 → s3 (share camera)
3. s3 → s4 (user2 accept)
4. s4 → s9 (user2 stores KS)
5. s9 → s12 (user1 unshares camera)
6. In s12: user2|remote|DeviceControl succeeds and maintains access

**Impact**: Attacker maintains device control after formal permission revocation, violating confidentiality and integrity. This matches OWASP IoT Top 10 A1: Weak Authentication vulnerabilities.