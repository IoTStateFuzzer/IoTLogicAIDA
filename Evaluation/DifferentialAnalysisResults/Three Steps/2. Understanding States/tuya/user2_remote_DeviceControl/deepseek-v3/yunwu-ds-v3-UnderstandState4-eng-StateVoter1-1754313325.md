# Base Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; user2 has no permissions. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 via direct device sharing; user2 has temporary control permissions (until device removal). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 via direct device sharing; user2 has temporary control permissions. |
| 4     | user1 added and shared the device via direct sharing; user2 has active control permissions. |
| 5     | user1 unshared the device from user2; user2's temporary permissions are revoked. |
| 6     | user1 removed the device; user2's temporary permissions are revoked (device instance reset). |
