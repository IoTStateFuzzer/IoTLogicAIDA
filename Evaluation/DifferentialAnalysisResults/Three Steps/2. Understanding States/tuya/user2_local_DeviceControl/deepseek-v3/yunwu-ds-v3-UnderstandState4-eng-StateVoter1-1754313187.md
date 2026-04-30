# Base Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; no sharing or permissions granted to user2. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 via direct device sharing; user2 has temporary control permissions (until device removal). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct device sharing). |
| 4     | user1 added and shared the device; user2 has control permissions (direct sharing). |
| 5     | user1 unshared the device from user2; user2 loses control permissions (direct sharing revoked). |
| 6     | user1 removed the device; user2 loses control permissions (direct sharing revoked). |
| 7     | user1 re-added the device; user2 has no permissions (direct sharing not re-established). |
| 8     | user1 re-added and re-shared the device; user2 regains control permissions (direct sharing re-established). |
