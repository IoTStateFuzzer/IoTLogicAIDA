

# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Initial state: No device bound|
|1 | Device added by user1 (owner), no sharing|
|2 | Error state (invalid actions lead here)|
|3 | Plug shared: user2 has full control permissions|
|4 | Shared state with attacker's knowledge captured (KS)|
|5 | Unshared state but attacker retains API replay capability|
|6 | Device removed by owner|
|7 | Device re-bound by owner but not shared|
|8 | Device re-shared after removal cycle|

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Persistent Unauthorized Control After Permission Revocation
**Impact effect**: Attacker maintains device control capabilities after legitimate permission revocation through API replay.

**Attack Path** :
1. Attackers accumulate knowledge through legitimate "user2|local|DeviceControl" operation in shared state (s3 -> s4)
2. Owner revokes permissions via "UnsharePlug" action (s4 -> s5)
3. Attacker replays "user2|local|DeviceControl" in state s5:
   - Successfully executes device control (operation result: Success)
   - Maintains persistent control state (s5 -> s5)

**Vulnerability Analysis**:
In state s5 (post-unsharing), the divergent model allows successful execution of "user2|local|DeviceControl" through API hooking despite revoked permissions. This violates the security expectation that: 
- Permission revocation (UnsharePlug) should immediately terminate all access
- Subsequent control attempts should fail with "NoElement" response (as in base model's s1 state)
- The success response leaks operational confirmation, enabling attackers to verify their continued access

**Security Implications**:
- Integrity Violation: Attacker maintains unauthorized control of device
- Non-Repudiation Failure: System fails to enforce permission revocation
- Information Disclosure: Success responses confirm continued access validity