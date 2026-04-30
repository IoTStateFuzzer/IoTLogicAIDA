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
| 4     | user1 added and shared the device with user2; user2 has temporary control permissions under direct sharing. |  
| 5     | user1 revoked user2's temporary control permissions after direct sharing. |  
| 6     | user1 removed the device after direct sharing, automatically revoking user2's temporary permissions. |
