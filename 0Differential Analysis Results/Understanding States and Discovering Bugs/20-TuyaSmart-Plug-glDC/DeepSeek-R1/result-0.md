

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. User1 can add devices, no actions for User2.
1 | Device added by User1. User1 can share/unshare/control device. User2 has no access.
2 | Invalid state (NoElement responses). Indicates failed operations from invalid states.
3 | Device shared with User2 via UI. User2 can click DeviceControl (legitimate access).
4 | User2 has executed local DeviceControl (stored in KS). Both users can control device.
5 | User1 unshared device (from s4). User2 retains KS access to replay DeviceControl.
6 | Device removed by User1. User2's DeviceControl fails (proper revocation).
7 | Device re-added after removal. User1 can share again. User2's access attempts fail.
8 | Device re-shared. User2 can control via KS but UI access may be revoked.

# Critical Vulnerability report
## Vulnerability 1: Persistent Access After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attacker gains temporary legitimate access through device sharing
2. User revokes sharing permission through normal UI operation
3. Attacker maintains persistent control capability through API replay

**Repeat Steps**:
1. s0 → s1 (User1 adds device)
2. s1 → s3 (User1 shares device)
3. s3 → s4 (User2 clicks DeviceControl - legitimate access)
4. s4 → s5 (User1 unshares device)
5. s5 remains vulnerable to: user2|local|DeviceControl (successful attack via KS replay)

**Impact Analysis**:
In state s5 (post-unshare state):
- Attacker's KS retains "user2|local|DeviceControl"
- System fails to invalidate previous authorization credentials
- Allows continuous device control after permission revocation
- Violates CIA triad through:
  - Integrity: Unauthorized state changes
  - Confidentiality: Persistent access to device status
  - Availability: Unauthorized control persists

**Evidence in State Machine**:
Basemodel properly returns to s1 after unsharing (complete permission cleanup). Statefuzzing creates s5 where:
- User1's UnsharePlug transitions to s5 instead of s1
- s5 permits User2's DeviceControl via stored KS action
- System fails to update attacker's knowledge set post-revocation

**Mitigation Recommendation**:
1. Implement strict permission revocation checks before API execution
2. Invalidate session tokens/credentials during unshare operations
3. Synchronize KS cleanup with UI permission changes