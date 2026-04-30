# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct sharing); user2 has not yet accepted. |
| 4     | user1 added the device and shared it with user2 (direct sharing); user2 accepted and now has temporary control permissions. |

# Divergent Model
| State | Semantic Description |  
|-------|----------------------|  
| 0     | Initial state. |  
| 1     | user1 added the device; no sharing or permissions exist for user2. |  
| 2     | Error state. |  
| 3     | user1 added the device and shared it with user2 (direct sharing); user2 has not yet accepted. |  
| 4     | user1 added and shared the device with user2; user2 accepted and gained control permissions (direct sharing). |  
| 5     | user1 added, shared, then unshared the device with user2; user2's direct sharing permissions revoked. |  
| 6     | user1 added, shared, then removed the device; user2's direct sharing permissions invalidated. |  
| 7     | user1 added, shared, unshared, then reshared the device with user2; user2 must accept again to regain direct sharing permissions. |
