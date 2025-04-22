

# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Initial state: No device bound|
|1 | Device bound by user1, no sharing|
|2 | Error state (invalid operations)|
|3 | Normal operation: user1 and user2 both have control permissions|
|4 | Shared state with attacker's API knowledge recorded|
|5 | Unshared state with attacker's API knowledge retained|
|6 | Device removed state with attacker's API knowledge|

# Base model report
**Problem description**: Shared permissions without consent requirement  
The base model implements sharing through "user1|local|SharePlug" which directly grants user2 full control permissions without requiring any consent/acceptance operation from user2. This violates the principle of least privilege and enables potential permission abuse.

**Problem Path** :
1. s0: Initial state -> s1 via user1|local|AddDevice
2. s1: Owner shares device -> s3 via user1|local|SharePlug
3. s3: Attacker gains permanent remote control via user2|remote|DeviceControl without consent

# Divergent model report
## Vulnerability 1: Persistent API Knowledge After Permission Revocation
**Impact effect**: Attacker retains API call capability to verify device existence even after permission revocation

**Attack Path** :
1. Attackers accumulate knowledge through legal remote control in state s3
2. User1 revokes permission via UnsharePlug (s3 -> s5)
3. Attacker replays API call in state s5:
   - s5 -> s5 via user2|remote|DeviceControl returns "Failed" response
   - Failed response confirms device still exists (contrast with s6's identical failure response)

**Security Impact**:
- Information leakage: Differentiates between device-unbound (s6) and permission-revoked (s5) states through same failure response
- Enables attackers to verify target device's existence even after permission revocation
- Violates CIA triad's Confidentiality requirement