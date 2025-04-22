

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added. User1 can add devices.
1 | Device added by user1. User1 can share/remove/control device. User2 has no access.
2 | Error state: Invalid operations performed from previous state.
3 | Device shared by user1 (pending acceptance). User2 can accept share.
4 | User2 has accepted device share. Both users can control device.
5 | Derived from s4 after user2 controls device. User1 can unshare/remove device.
6 | After unsharing from s5. User1 can reshare device. **User2 retains device control (anomalous)**.
7 | Device reshared by user1. User2 can re-accept share (redundant transition to s5).
8 | Device removed. User2's control attempts fail. User1 can re-add device.

# Critical Vulnerability report
## Vulnerability 1: Persistent Unauthorized Device Control After Unshare
**Threat Level**: High Risk

**Attack Path**:
1. Attacker (user2) gains temporary access through legitimate sharing (s0→s1→s3→s4)
2. Victim (user1) revokes sharing privileges (s4→s5→s6)
3. Attacker retains active device control capabilities despite revocation

**Repeat Steps**:
1. s0 → s1 via "user1|local|AddDevice"
2. s1 → s3 via "user1|local|SharePlug"
3. s3 → s4 via "user2|remote|AcceptDeviceShare"
4. s4 → s5 via "user2|remote|DeviceControl"
5. s5 → s6 via "user1|local|UnsharePlug"
6. **In s6**: Attacker successfully executes "user2|remote|DeviceControl" despite revocation

**Security Impact**:
- Integrity Violation: Attacker maintains control of device after permission revocation
- Confidentiality Breach: Attacker can monitor device status post-access removal
- Non-Repudiation Failure: System fails to properly terminate user session/access rights

**Root Cause**:
- Missing authorization check when processing device control requests
- Server maintains active session for user2 after unshare operation
- State transition s5→s6 doesn't clear attacker's access privileges

**Evidence in State Machine**:
- In basemodel: Unshare operation (s4→s1) properly revokes user2 access
- In statefuzzing: Unshare operation (s5→s6) allows continued user2 control (s6→s6 via DeviceControl)