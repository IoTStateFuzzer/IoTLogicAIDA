

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added
1 | User1 has added a device (Plug) with full control
2 | Error/Invalid state (operations unavailable)
3 | User1 shared Plug with User2 (valid sharing exists)
4 | User2 successfully controlled device post-sharing (KS recorded)
5 | User1 revoked sharing but User2 retains KS access
6 | User1 removed device completely
7 | User1 re-added new device after removal
8 | User1 re-shared new device with User2

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Permission Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attacker gains initial control through legitimate sharing
2. Maintains local control capability after permission revocation
3. Achieves persistent unauthorized access through stale credentials

**Repeat Steps**:
1. s0 → s1 (User1 adds device)
2. s1 → s3 (User1 shares Plug)
3. s3 → s4 (User2 controls device, KS updated)
4. s4 → s5 (User1 revokes sharing)
5. In s5: User2|local|DeviceControl remains successful

**Analysis**:
The statefuzzing model reveals a critical divergence in state s5 where:
- BaseModel would revoke all access after UnsharePlug (s3→s1)
- StateFuzzing allows continued local control (s5→s5 with success)

This violates the CIA triad through:
1. **Integrity Failure**: Attacker maintains control capability post-revocation
2. **Confidentiality Risk**: Device status remains exposed to attacker
3. **Availability Threat**: Legitimate owner's control could be interfered

## Vulnerability 2: Cross-Device Session Credential Reuse
**Threat Level**: Medium Risk

**Attack Path**:
1. Attacker captures device credentials
2. Maintains access through device removal/re-add cycles
3. Reuses credentials on new device instances

**Evidence**:
- s6 (device removed) → s7 (new device added)
- s7 → s8 (reshare operation)
- s8 → s4 (attacker regains control using old KS)

**Security Impact**:
Allows attackers to bridge security boundaries between device instances through improper credential binding.