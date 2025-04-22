

# State Semantic mapping table

| State | Semantic Description |
|-------|-----------------------|
| 0     | Initial state: No devices added, no users invited. |
| 1     | Device added by user1. User2 not invited. |
| 2     | Error state: No operations possible. |
| 3     | User2 invited but no device added. |
| 4     | Device added and user2 invited (both have control). |
| 5     | Attacker (user2) has API hooking capability (KS=[*]). Both users retain device control. |
| 6     | Device removed, but attacker retains API knowledge (KS=[*]). User2 lacks control. |
| 7     | User2 removed from home. Attacker retains API knowledge (KS=[*]) but lacks permissions. |
| 8     | Device re-added after removal. User2 not re-invited. Attacker retains KS=[*]. |
| 9     | Device added and user2 re-invited (legitimate control restored). |
| 10    | Device added and user2 invited. Attacker can control via UI/API. |

# Base model report

**Problem description**: Information leakage via inconsistent error codes.  
**Problem Path**:  
1. **s3**: user1 removes user2 via `user1|local|RemoveFromHome` → transitions to s2 (device retained).  
2. **s2**: user2 attempts `user2|remote|DeviceControl` → receives `NoElement` (no distinction between device removal vs permission revocation).  

**Impact**: The base model’s error handling does not leak device existence, but the divergent model introduces this flaw.

# Divergent model report

## Vulnerability 1: Information Leakage via Error Code Differentiation  
**Impact effect**: Attacker distinguishes between device removal and permission revocation.  

**Attack Path**:  
1. **s4**: user2 controls device via UI, storing API parameters (KS=[*]).  
2. **s5 → s6**: user1 removes device → user2’s replay attack in s6 returns *"500000404"* (device not found).  
3. **s5 → s7**: user1 removes user2 → user2’s replay in s7 returns *"500000401"* (unauthorized).  

**Impact**: User2 infers whether the device exists or their access was revoked, violating confidentiality.  

## Vulnerability 2: Stale Permissions via State Retention  
**Impact effect**: Attacker retains API control in invalid states.  

**Attack Path**:  
1. **s4 → s5**: user2 controls device, storing KS=[*].  
2. **s5 → s9**: user1 re-invites user2 → s9 retains KS=[*], allowing continued API access.  

**Impact**: Attacker leverages stale credentials to maintain control despite permission changes.  

---

**Conclusion**: The divergent model introduces critical information leakage and permission retention flaws absent in the base model.