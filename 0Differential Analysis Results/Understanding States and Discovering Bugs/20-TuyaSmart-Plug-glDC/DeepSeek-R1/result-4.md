

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. user1 can add devices; user2 has no permissions.
1 | Device added by user1. user1 can control/share/remove device; user2 has no access.
2 | Error state (invalid operation attempted). No valid operations available.
3 | Device shared with user2 (valid sharing). Both users have control permissions.
4 | user2 has actively used device control after sharing. Maintains same permissions as s3.
5 | user1 unshared device after s4 state. Abnormal persistence of user2's local control.
6 | Device removed by user1. Clean state similar to s0 but with KS retention.
7 | Device re-added after removal. Equivalent to s1 but with attacker KS present.
8 | Device re-shared after removal cycle. Similar to s3 but with expanded attack surface.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attacker accumulates device control knowledge through legitimate sharing
2. Replay local control action after permission revocation
3. Bypass access revocation check to maintain persistent device control

**Repeat steps**:
1. s0 → s1 (user1 adds device)
2. s1 → s3 (user1 shares device)
3. s3 → s4 (user2 controls device)
4. s4 → s5 (user1 unshares device)
5. In s5: user2|local|DeviceControl remains operational

**Impact Analysis**:
The statefuzzing model reveals dangerous permission retention in s5 state where:
- Base model would return to s1 (clean revocation)
- Statefuzzing maintains user2's control capability through:
  - KS retention of "user2|local|DeviceControl"
  - Failed permission revocation in API layer
  - State-specific authorization bypass

This creates a privilege persistence vulnerability violating integrity and confidentiality through:
1. Continued device control after permission revocation
2. Silent privilege maintenance without user1's knowledge
3. Potential lateral movement using retained access

## Vulnerability 2: State-dependent Authorization Bypass
**Threat Level**: Medium Risk

**Attack Path**:
1. Leverage knowledge set from previous valid operations
2. Exploit state transition inconsistencies
3. Achieve device control in supposedly invalid states

**Evidence**:
- s8 → s4 transition via user2|local|DeviceControl shows:
  - Re-acquisition of full privileges without fresh sharing
  - Authorization check dependency on previous KS rather than current state
- s5 maintains local control channel while blocking remote

**Impact**:
Creates inconsistent security posture where:
- Attacker maintains "zombie" access channels
- Security controls become state-dependent rather than policy-based
- Partial revocation enables attack surface regeneration