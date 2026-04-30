# Base Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; user2 has no permissions. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 via direct device sharing; user2 has temporary control permissions (revoked if device is removed or re-added). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 via direct device sharing. |
| 4     | user1 added and shared the device; user2 has temporary control permissions through direct sharing. |
| 5     | user1 revoked user2's direct sharing permissions. |
| 6     | user1 removed the device, automatically revoking all permissions (including user2's temporary permissions). |
| 7     | user1 re-added the device; user2 has no permissions (direct sharing was previously revoked). |
| 8     | user1 re-added the device and established new direct sharing with user2, granting temporary control permissions. |
