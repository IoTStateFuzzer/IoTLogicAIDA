

# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Initial state (no devices bound)|
|1 | user1 owns the device (plug)|
|2 | Error state (invalid operations)|
|3 | user1 has shared plug with user2 (both have control permissions)|
|4 | user2 has performed remote DeviceControl with knowledge capture|
|5 | user1 revoked sharing but attacker retains replay knowledge|
|6 | user1 removed device but attacker retains replay knowledge|

# Base model report
**Problem description**: No security issues found in base model
**Problem Path** : N/A

# Divergent model report
## Vulnerability 1: Persistent Control After Permission Revocation
**Impact effect**: Attacker maintains device control capability after legitimate permission revocation

**Attack Path** :
1. Attackers accumulate knowledge through legitimate remote DeviceControl operation in state s3
2. After owner revokes permissions (transition to s5)
3. Attacker replays DeviceControl action in state s5:
   - s0 -> s1 (user1 AddDevice)
   - s1 -> s3 (user1 SharePlug)
   - s3 -> s4 (user2 remote DeviceControl - knowledge captured)
   - s4 -> s5 (user1 UnsharePlug)
   - s5: user2|remote|DeviceControl (replay attack)

**Vulnerability Analysis**:
In state s5 (post-revocation state), the divergent model allows:
1. Attacker retains API call knowledge ([*] in KS field)
2. Replay attempt receives "Failed" response but maintains state s5
3. Device control failure response reveals continued device existence (information leakage)
4. State s5 allows re-sharing back to s4 through user1's SharePlug action, creating a potential cyclic permission abuse scenario

**Mitigation Recommendation**:
1. Clear attacker's knowledge set after permission revocation
2. Return generic "access denied" instead of device-specific failure messages
3. Invalidate previous session tokens during unsharing operation