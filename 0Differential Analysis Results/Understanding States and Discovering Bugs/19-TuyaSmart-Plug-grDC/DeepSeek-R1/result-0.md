

# State Semantic mapping table

| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state: No device added. |
| 1     | Device added by user1. user1 has full control. user2 has no permissions. |
| 2     | Error state: Invalid for all operations. |
| 3     | Device shared with user2. Both users have local/remote control permissions. |
| 4     | Special shared state: Attacker has API replay capability (KS=[*]). Both users retain control. |
| 5     | user1 revoked sharing. user2 lost UI access (CK=[]), but attacker retains API replay knowledge. |
| 6     | Device removed by user1. All permissions revoked. |

# Base model report
Every thing is OK.

# Divergent model report
Every thing is OK.