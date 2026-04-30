# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state.       |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state.         |
| 3     | user1 added the device and shared it with user2 via direct device sharing; user2 has not yet accepted the share. |
| 4     | user1 added the device and shared it with user2 via direct device sharing; user2 accepted the share and now has control permissions for this device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 via direct device sharing. |
| 4     | user1 added the device, shared it with user2, and user2 accepted the share. |
| 5     | user1 added the device, shared it with user2, user2 accepted the share, and gained control permissions. |
| 6     | user1 added the device, shared it with user2, user2 accepted the share, gained control permissions, and user1 unshared the device. |
| 7     | user1 added the device, shared it with user2, user2 accepted the share, gained control permissions, user1 unshared the device, and reshared it with user2. |
| 8     | user1 added the device, shared it with user2, user2 accepted the share, gained control permissions, and user1 removed the device. |

