# Base Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and shared it with user2 via direct sharing; user2 has not yet accepted the invitation. |
| S4    | user1 added the device and shared it with user2 via direct sharing; user2 accepted the invitation and now has control permissions limited to this device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| S0    | Initial state. |
| S1    | user1 added the device; user2 has no permissions. |
| S2    | Error state. |
| S3    | user1 added the device and shared it with user2; user2 has not yet accepted the invitation. |
| S4    | user1 added the device and shared it with user2; user2 accepted the invitation and now has control permissions. |
| S5    | user1 added the device, shared it with user2, and then unshared it; user2's permissions are revoked. |
| S6    | user1 added the device, shared it with user2, and then removed the device; user2's permissions are revoked. |
| S7    | user1 added the device, shared it with user2, unshared it, and then reshared it; user2 must accept again to regain permissions. |
