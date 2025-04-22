# State Semantic Mapping Table
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state |
| s1    | Device added by user1 |
| s2    | Error state (NoElement) |
| s3    | Device shared with user2 |
| s4    | User2 has control permissions (local and remote) |
| s5    | User2's control permissions revoked |
| s6    | Device removed by user1 |

# Base Model Report
Everything is OK.

# Divergent Model Report
## Vulnerability 1: Unauthorized Remote Control by User2
**Impact effect**: User2 can control the device remotely even after their permissions have been revoked by user1.

**Attack Path**:
1. User1 adds the device (s0 -> s1).
2. User1 shares the device with user2 (s1 -> s3).
3. User2 controls the device remotely and accumulates knowledge (s3 -> s4).
4. User1 revokes user2's permissions (s4 -> s5).
5. User2 replays the remote control action using the accumulated knowledge (s5 -> s4).

In this scenario, user2 is able to regain control of the device remotely by replaying the remote control action using the knowledge accumulated before their permissions were revoked. This allows user2 to bypass the permission revocation and continue controlling the device, posing a security risk to user1.