# Base Model
| State | Semantic Description |  
|-------|----------------------|  
| S0    | Initial state. |  
| S1    | user1 added the device; user2 has no permissions. |  
| S2    | Error state. |  
| S3    | user1 added the device and shared it with user2 via direct device sharing; user2 has temporary control permissions (until device removal). |

# Divergent Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 (direct device sharing). |  
| 4     | user1 added and shared the device with user2; user2 has temporary control permissions under direct sharing. |  
| 5     | user1 revoked user2's direct sharing permissions, removing user2's control. |  
| 6     | user1 removed the device, revoking all permissions (including user2's temporary control). |  
| 7     | user1 re-added the device; user2 has no permissions unless direct sharing is re-established. |  
| 8     | user1 re-added the device and reshared it with user2 (direct sharing restored). |
