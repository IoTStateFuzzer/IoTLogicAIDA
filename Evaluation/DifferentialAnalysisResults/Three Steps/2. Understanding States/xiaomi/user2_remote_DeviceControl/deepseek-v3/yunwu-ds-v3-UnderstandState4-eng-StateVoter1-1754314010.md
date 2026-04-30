# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and directly shared it with user2; user2 has not yet accepted the invitation. |
| S4    | user1 added the device and directly shared it with user2; user2 accepted the invitation and gained control permissions for this device instance. |
| S5    | user1 added, shared, then removed the device; user2's direct device permissions are revoked. |
| S6    | user1 re-added the device after removal; user2 has no permissions (direct sharing was revoked and requires re-sharing). |
| S7    | user1 re-added the device and directly re-shared it with user2; user2 has not yet accepted the new invitation. |
| S8    | user1 re-added the device and directly re-shared it with user2; user2 accepted the new invitation and regained control permissions for this device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and directly shared it with user2 (pending manual acceptance). |
| 4     | user1 added and directly shared the device; user2 manually accepted and gained control permissions. |
| 5     | user1 added, directly shared, then removed the device; user2's permissions were revoked. |
| 6     | user1 re-added the device after removal; user2 has no permissions unless reshared. |
| 7     | user1 re-added and directly reshared the device with user2 (pending manual acceptance). |
| 8     | user1 re-added and directly reshared the device; user2 manually accepted and gained control permissions. |
| 9     | user1 directly shared the device; user2 manually accepted and exercised control. |
| 10    | user1 removed the device after user2's control; user2's permissions were revoked. |
| 11    | user1 re-added the device after removal; user2 has no permissions unless reshared. |
| 12    | user1 unshared the device from user2 after control; user2's permissions were revoked. |
| 13    | user1 unshared then directly reshared the device with user2 (pending manual acceptance). |
| 14    | user1 re-added and directly reshared the device after removal (pending manual acceptance). |
| 15    | user1 unshared, directly reshared, then removed the device; user2's permissions were revoked. |
| 16    | user1 re-added the device after unsharing and removal; user2 has no permissions unless reshared. |
| 17    | user1 re-added and directly reshared the device after unsharing and removal (pending manual acceptance). |
| 18    | user1 re-added and directly reshared the device; user2 manually accepted and gained control permissions. |
| 19    | user1 re-added and directly reshared the device; user2 manually accepted and exercised control. |
| 20    | user1 unshared the device after user2's control; user2's permissions were revoked. |
| 21    | user1 unshared then directly reshared the device with user2 after control (pending manual acceptance). |
| 22    | user1 re-added and directly reshared the device; user2 manually accepted the share after prior removal. |
