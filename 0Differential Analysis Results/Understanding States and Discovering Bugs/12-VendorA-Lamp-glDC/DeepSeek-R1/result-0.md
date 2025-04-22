

# State Semantic mapping table
| State | Semantic Description |
|-------|-----------------------|
| 0     | Initial state - No devices added, no users invited. |
| 1     | Device added by user1. User1 has full control. |
| 2     | Error state - No operations possible. |
| 3     | User2 is invited and accepted by user1, but no device added yet. User2 has no permissions. |
| 4     | Device added + user2 invited. Both users have control permissions. Attacker can click UI. |
| 5     | User2 has active control permissions (via UI click). KS contains DeviceControl knowledge. |
| 6     | Device removed by user1. User2 attempts local control but fails (no permissions). |
| 7     | User2 removed from home by user1. User2 retains DeviceControl via API hooking. |
| 8     | User2 removed + device removed. User2's control attempts fail. |
| 9     | New device added after removal. User2 has no permissions. |
| 10    | User1 re-invites user2 after device removal. Both have permissions again. |

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Stale Permission Retention After Removal
**Impact effect**: Attacker maintains device control after being removed from home  

**Attack Path**:
1. Legitimate scenario: user1 adds device (s0→s1) ➔ invites user2 (s1→s4)  
2. Attacker accumulates knowledge by controlling device locally (s4→s5 via "user2|local|DeviceControl")  
3. User1 removes attacker from home (s5→s7 via RemoveFromHome)  
4. Attacker replays DeviceControl in s7:  
   - Successfully executes control commands (s7 remains s7)  
   - Retains device control despite permission revocation  

This violates CIA triad by allowing unauthorized access (Integrity breach) after permission revocation. The divergent model's s7 state preserves attacker's control capability through API hooking even after formal permission removal.