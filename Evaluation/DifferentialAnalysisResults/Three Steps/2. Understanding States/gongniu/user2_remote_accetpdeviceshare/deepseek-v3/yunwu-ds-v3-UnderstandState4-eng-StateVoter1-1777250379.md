# Base Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; user2 has no permissions. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2; user2 has not accepted the share yet. |  
| 4     | user1 added the device and shared it with user2; user2 accepted the share and has control permissions (direct device sharing). |

# Divergent Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; user2 has no permissions. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2; user2 has not accepted the share yet. |  
| 4     | user1 added the device and shared it with user2; user2 accepted and has temporary control permissions. |  
| 5     | user1 added the device, shared it with user2, user2 accepted, then user1 unshared; user2 no longer has permissions. |  
| 6     | user1 added the device, shared it with user2, user2 accepted, then user1 removed the device; user2 no longer has permissions. |  
| 7     | user1 added the device, shared it with user2, user2 accepted, user1 unshared, then reshared; user2 has temporary control permissions again. |
