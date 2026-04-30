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
| 1     | user1 added the device. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 via direct device sharing. |  
| 4     | user1 added and shared the device; user2 has temporary control permissions under direct sharing. |  
| 5     | user1 unshared the device from user2; user2's direct-sharing permissions are revoked. |  
| 6     | user1 removed the device; all permissions (including user2's) are revoked. |
