# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct sharing); user2 has not accepted the invitation yet. |
| 4     | user1 added the device and shared it with user2; user2 accepted the share, gaining temporary control permissions (direct sharing). |
| 5     | user1 added, shared, then removed the device; user2's direct sharing permissions are revoked. |
| 6     | user1 re-added the device after removal; user2 has no permissions (direct sharing was revoked and requires resharing). |
| 7     | user1 re-added the device and re-shared it with user2; user2 has not accepted the invitation yet. |
| 8     | user1 re-added the device and re-shared it with user2; user2 accepted the share, regaining temporary control permissions (direct sharing). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device (1st instance). |
| 2     | Error state. |
| 3     | user1 added the device (1st instance) and shared it with user2 via direct device sharing (pending user2's manual acceptance). |
| 4     | user1 added the device (1st instance), shared it with user2 via direct device sharing, and user2 manually accepted the share (direct sharing permissions active). |
| 5     | user1 removed the device (1st instance) after sharing, revoking user2's direct sharing permissions. |
| 6     | user1 re-added the device (2nd instance); user2 has no permissions as direct sharing was revoked and not yet re-established. |
| 7     | user1 re-added the device (2nd instance) and reshared it with user2 via direct device sharing (pending user2's manual acceptance). |
| 8     | user1 re-added the device (2nd instance), reshared it with user2 via direct device sharing, and user2 manually accepted the share (direct sharing permissions re-activated). |
