# Tips
Experiment for understanding states
# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state. |
| 1 | user1 added the device; user2 has no permissions. |
| 2 | Error state. |
| 3 | user1 added the device and shared it with user2 (direct device sharing); user2 has not yet accepted the invitation. |
| 4 | user1 added the device and shared it with user2 (direct device sharing); user2 accepted the invitation and now has control permissions for this device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct device sharing); user2 has not yet accepted. |
| 4     | user1 added and shared the device; user2 accepted the share but has not yet controlled it (direct sharing). |
| 5     | user1 added and shared the device; user2 accepted and gained control permissions (direct sharing). |
| 6     | user1 unshared the device from user2 after user2 had control permissions (direct sharing ends). |
| 7     | user1 reshared the device with user2 after previous unsharing; user2 must accept again (direct sharing re-initiated). |
| 8     | user1 removed the device after sharing; user2's permissions are revoked (direct sharing ends). |

