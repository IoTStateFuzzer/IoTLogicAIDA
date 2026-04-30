# Tips
Experiment for understanding states
# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state. |
| 1 | user1 added the device; user2 has no permissions. |
| 2 | Error state. |
| 3 | user1 added the device and shared it with user2 via direct device sharing; user2 has not yet accepted the invitation. |
| 4 | user1 added the device and shared it with user2 via direct device sharing; user2 accepted the invitation and now has control permissions for this specific device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct device sharing). |
| 4     | user1 added and shared the device; user2 accepted the share (direct device sharing permissions active). |
| 5     | user1 added and shared the device; user2 accepted and gained control permissions (direct device sharing active). |
| 6     | user1 unshared the device after user2 had control (user2's direct device sharing permissions revoked). |
| 7     | user1 reshared the device after unsharing (user2 must re-accept to regain direct device sharing permissions). |
| 8     | user1 removed the device after sharing and user2's control (all direct device sharing permissions permanently revoked). |

