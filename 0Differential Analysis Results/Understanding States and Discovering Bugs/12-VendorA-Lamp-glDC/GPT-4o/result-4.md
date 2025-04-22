# State Semantic Mapping Table

| State | Semantic Description |
|-------|-----------------------|
| s0    | Initial state |
| s1    | Error state, no operations are executable |
| s2    | User1 has removed the device |
| s3    | User1 has invited and user2 has accepted the invitation |
| s4    | User1 has invited and user2 has accepted the invitation, user2 has control permissions |
| s5    | User2 has successfully controlled the device locally |
| s6    | User1 has removed the device, user2 has control permissions |
| s7    | User1 has removed user2 from the home, user2 has control permissions |
| s8    | User1 has removed the device, user2 has control permissions |
| s9    | User1 has invited and user2 has accepted the invitation, user2 has control permissions |
| s10   | User1 has removed the device, user2 has control permissions |

# Base Model Report

Everything is OK.

# Divergent Model Report

## Vulnerability 1: Unauthorized Device Control by User2
**Impact effect**: User2 can control the device even after being removed from the home by User1.

**Attack Path**:
1. User1 invites User2 and User2 accepts the invitation (s0 -> s3).
2. User2 controls the device locally (s4 -> s5).
3. User1 removes User2 from the home (s5 -> s7).
4. User2 still has control permissions and can control the device (s7 -> s7).

This vulnerability allows User2 to retain control over the device even after User1 has removed them from the home, posing a significant security risk.