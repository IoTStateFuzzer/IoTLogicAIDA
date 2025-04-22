

# State Semantic mapping table
| State | Semantic Description |
|-------|-----------------------|
| 0     | Initial state. No devices added, no users invited. |
| 1     | User1 has added a device. User2 has no permissions. |
| 2     | Error state. No actions are executable. |
| 3     | User1 invited and user2 accepted, but no device added yet. User2 has home membership but no device control. |
| 4     | User1 added device after invitation. Both users have legitimate control permissions. |
| 5     | User2 gained control via API hooking. Attacker retains knowledge (KS) but cannot click UI. |
| 6     | User1 removed the device. User2 attempts control via stored knowledge but fails. |
| 7     | User1 removed user2 from home. User2 has no permissions. |
| 8     | Device removed and user2 re-invited. Transitional state with partial permissions. |
| 9     | User1 re-added device after removing user2. User2 lacks access. |
| 10    | User1 re-added device without revoking user2's home membership. Both have legitimate control. |

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Information Leakage via Error Code Differentiation
**Impact effect**: User2 can infer device existence/status through error codes after losing permissions, violating confidentiality.

**Attack Path** :
1. Legitimate invitation process creates state s4 where user2 has control permissions.
2. User1 removes the device (transition to s6) or removes user2 from home (transition to s7).
3. User2 replays `user2|remote|DeviceControl`:
   - In s6: Receives error code 500000404 ("device not found"), indicating device removal.
   - In s7: Receives error code 500000401 ("unauthorized"), indicating permission revocation.
4. Error code differentiation allows user2 to determine whether:
   - The device still exists in the system (404 → removed)
   - Their access was revoked (401 → still present but unauthorized)

This leaks system state information to unauthorized users, enabling attackers to profile device management activities.