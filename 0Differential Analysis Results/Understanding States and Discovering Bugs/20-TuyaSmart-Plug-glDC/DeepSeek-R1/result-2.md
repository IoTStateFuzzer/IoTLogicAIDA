

# State Semantic mapping table
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. No devices bound. |
| 1     | User1 has bound a device. User2 has no permissions. |
| 2     | Error state (invalid operations). |
| 3     | User1 shared device with User2. Both have full control permissions. |
| 4     | User2 gained control via local channel (attack path). User1 still has device. |
| 5     | User1 revoked sharing (UnsharePlug) but User2 retains local control capability. |
| 6     | User1 removed device. Both lose permissions. |
| 7     | User1 re-bound device. User2 has no permissions. |
| 8     | User1 re-shared device. Both have permissions again. |

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Persistent Local Control After Permission Revocation
**Impact effect**: Attacker maintains local device control after legitimate permission revocation.

**Attack Path**:
1. Legitimate sharing: s0 -> s1 (AddDevice) -> s3 (SharePlug)
2. Attacker gains local control: s3 -> s4 via user2|local|DeviceControl
3. Owner revokes permission: s4 -> s5 via user1|local|UnsharePlug
4. **Vulnerable state**: In s5, user2|local|DeviceControl remains operational with success response

**Analysis**:
- After UnsharePlug operation (s5), the base model would return to s1 where User2 has no permissions
- Divergent model allows continued successful local control in s5 (KS:[*] enables API hooking), violating permission revocation semantics
- Impact: Compromises confidentiality and integrity (CIA triad) as revoked user retains control capability

## Vulnerability 2: State Desynchronization Attack
**Impact effect**: Attacker can reactivate legacy permissions through state confusion

**Attack Path**:
1. After device removal (s6 -> s7 via AddDevice)
2. New sharing: s7 -> s8 via SharePlug 
3. Attacker uses old local control: s8 -> s4 via user2|local|DeviceControl
4. **Vulnerable state**: s4 contains different permission context than base model's equivalent state

**Analysis**:
- Reactivation of previous attack state (s4) after new sharing creates permission ambiguity
- Enables attacker to bypass fresh permission context through state confusion
- Impact: Weakens non-repudiation and creates audit trail inconsistencies