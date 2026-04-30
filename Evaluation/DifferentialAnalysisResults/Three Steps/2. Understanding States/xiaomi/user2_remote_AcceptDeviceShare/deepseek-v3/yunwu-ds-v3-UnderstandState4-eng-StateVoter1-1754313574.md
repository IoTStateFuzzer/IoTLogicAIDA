# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and shared it with user2 (direct sharing); user2 has not yet manually accepted the invitation. |
| S4    | user1 added the device and shared it with user2; user2 accepted the invitation, gaining direct device control permissions. |
| S5    | user1 added, shared, then removed the device; user2's direct sharing permissions are revoked. |
| S6    | user1 re-added the device after removal; user2 has no permissions (direct sharing to be re-established). |
| S7    | user1 re-added the device and reshared it with user2; user2 has not yet manually accepted the new invitation. |
| S8    | user1 re-added the device and reshared it; user2 accepted the new invitation, regaining direct device control permissions. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device (1st instance). |
| 2     | Error state. |
| 3     | user1 added the device (1st instance) and shared it with user2 (direct sharing). |
| 4     | user1 added the device (1st instance), shared it with user2, and user2 accepted the share (direct sharing permissions granted). |
| 5     | user1 added the device (1st instance), shared it with user2, then removed the device (user2's direct sharing permissions revoked). |
| 6     | user1 re-added the device (2nd instance) after removal; user2 has no permissions unless reshared. |
| 7     | user1 re-added the device (2nd instance) and reshared it with user2 (direct sharing re-initiated). |
| 8     | user1 re-added the device (2nd instance), reshared it, and user2 accepted (direct sharing permissions re-granted). |
