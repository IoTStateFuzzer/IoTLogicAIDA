

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. user1 can add a device. user2 has no permissions.
1 | Device added by user1. user1 can share/unshare/control/remove device. user2 has no access.
2 | Error/Invalid state. All operations return NoElement or fail.
3 | Device shared by user1 (sharing pending acceptance). user2 can accept share to gain control.
4 | user2 has accepted share and gained device control permissions. user1 retains full control.
5 | Post-revocation persistence state (after user2 controlled device post-sharing). user2 retains control despite revocation.
6 | user1 revoked sharing (from s5). user2 still has active control permissions (incorrectly).
7 | Re-shared state after revocation. user2 can re-accept share and regain control.
8 | Device removed by user1. All operations except re-adding fail. user2 control attempts fail with explicit rejection.

# Critical Vulnerability report
## Vulnerability 1: Persistent Access After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attackers gain temporary legitimate access through device sharing
2. user1 revokes sharing permissions through normal UI operation
3. Attacker maintains persistent device control capabilities despite revocation

**Repeat Steps**:
1. s0 -> s1 (user1 adds device)
2. s1 -> s3 (user1 shares device)
3. s3 -> s4 (user2 accepts share)
4. s4 -> s5 (user2 controls device)
5. s5 -> s6 (user1 revokes sharing)
6. In s6: user2|remote|DeviceControl remains possible and effective

**Security Impact**:
- Integrity Violation: Attacker maintains write access to device states after permission revocation
- Non-Repudiation Failure: System fails to properly terminate session after access revocation
- Privilege Escalation: Temporary user maintains permanent access rights

## Vulnerability 2: State Desynchronization Attack
**Threat Level**: Medium Risk

**Attack Path**:
1. Attacker accumulates device control API knowledge while authorized
2. user1 removes device entirely
3. Attacker receives explicit failure response (s8), revealing device status

**Repeat Steps**:
1. Reach s8 through normal device removal
2. user2|remote|DeviceControl in s8 returns explicit "Operation failed" with error code 9017
3. Attacker can distinguish between "non-existent device" vs "no permissions"

**Security Impact**:
- Information Disclosure: Error differentiation reveals device existence status to unauthorized users
- Reconnaissance Aid: Helps attackers map network topology and user device ownership