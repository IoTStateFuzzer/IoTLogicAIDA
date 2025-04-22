

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No device added. User1 can add device (transition to s1). User2 has no permissions.
1 | Device added by user1. User1 can share device (to s3), control device, or remove device (back to s0). User2 cannot act.
2 | Error/Invalid state. All operations return NoElement. Indicates invalid action attempts from any user.
3 | Device shared by user1. User1 can unshare (back to s1) or remove device (to s0). User2 can accept share (to s4).
4 | User2 has accepted share and gained control. User1 can unshare (to s1) or remove device (to s0). User2 maintains control.
5 | Special persistence state after user2 device control. User1 operations lead to different unshare/remove paths. User2 retains control capabilities.
6 | Post-unshare state with residual permissions. User1 can reshare device (to s7). User2 still maintains device control privileges despite unshare.
7 | Reshared device state. User2 can re-accept share (to s5). Shows permission reactivation potential.
8 | Device removed state. User1 can re-add device (to s6). User2 control attempts fail (proper revocation).

# Critical Vulnerability report
## Vulnerability 1: Residual Access After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attacker gains initial access through legitimate sharing (s0→s1→s3→s4)
2. User1 revokes permissions via UnsharePlug (s4→s1 in base model, but s5→s6 in fuzzing model)
3. Attacker retains device control capability in post-unshare state (s6)

**Repeat Steps**:
1. s0 → s1 (AddDevice)
2. s1 → s3 (SharePlug)
3. s3 → s4 (user2 AcceptDeviceShare)
4. s4 → s5 (user2 DeviceControl)
5. s5 → s6 (user1 UnsharePlug)
6. In s6: user2|remote|DeviceControl → s6 (Success)

**Impact**: Attacker maintains operational control of device after permission revocation, violating authorization integrity. This enables persistent unauthorized access despite owner's revocation attempts.

## Vulnerability 2: Cross-Session Permission Persistence
**Threat Level**: Medium Risk

**Attack Path**:
1. Attacker accumulates device control knowledge (s4→s5)
2. User removes/re-adds device (s5→s8→s6 via RemoveDevice+AddDevice)
3. Attacker replays control without re-accepting share

**Repeat Steps**:
1. s0 → s1 → s3 → s4 → s5 (Normal sharing flow)
2. s5 → s8 (user1 RemoveDevice)
3. s8 → s6 (user1 AddDevice)
4. In s6: user2|remote|DeviceControl → s6 (Success)

**Impact**: Device removal/re-addition doesn't clear attacker's control capabilities. This violates session isolation principles, allowing historical permissions to affect new device instances.

## Vulnerability 3: Improper Share State Reset
**Threat Level**: Medium Risk

**Analysis**:
The statefuzzing model creates parallel permission states (s5/s6/s7 vs s3/s4) where unsharing transitions to s6 instead of s1. This allows:
1. User1 shares device (s1→s3)
2. User2 accepts (s3→s4)
3. User2 controls device (s4→s5)
4. User1 unshares (s5→s6)
5. User1 can reshare from s6→s7 without returning to base state
6. User2 retains previous control capabilities through state transitions

**Impact**: Creates multiple permission activation paths that bypass normal authorization checks, potentially enabling permission stacking and unexpected privilege retention.