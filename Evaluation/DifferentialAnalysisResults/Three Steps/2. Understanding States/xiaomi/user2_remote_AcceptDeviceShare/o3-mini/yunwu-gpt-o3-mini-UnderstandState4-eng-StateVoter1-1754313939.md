# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: user1 has not added any device and no sharing invitation has been initiated. |
| s1 | user1 added the device for the first time (device addition count = 1) without sending any sharing invitation; consequently, user2 has no permissions. |
| s2 | Error state. |
| s3 | user1 added the device (first instance) and initiated a direct sharing invitation (e.g., using ShareCamera); user2 is invited but has not yet accepted, so no control rights are granted. |
| s4 | user1 added the device (first instance) and issued a sharing invitation that user2 subsequently accepted, granting user2 direct control permissions for that device instance. |
| s5 | user1 added the device, initiated a sharing invitation, then removed the device; the removal revokes the device instance and any pending or active direct sharing, so user2 loses any permission. |
| s6 | After the initial device was removed, user1 re-added the device (device addition count = 2) without re-initiating a sharing invitation; thus, the prior share is revoked and user2 holds no permissions for the new instance. |
| s7 | user1 re-added the device (second instance) and initiated a new direct sharing invitation; user2 is invited for the current instance but has not yet accepted, so control rights remain pending. |
| s8 | user1 re-added the device (second instance), issued a new sharing invitation, and user2 accepted it, thereby granting user2 direct control rights for the current device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no sharing initiated. |
| s1 | User1 added the device for the first time (device addition count = 1) without initiating any sharing; user2 has no permissions. |
| s2 | Error state. |
| s3 | User1 added the device (first instance) and initiated a sharing invitation; user2 is invited but has not yet accepted the share. |
| s4 | User1 added the device and initiated a direct sharing action, which user2 accepted, granting user2 temporary direct control over that active device instance. |
| s5 | User1 added the device, initiated sharing, then removed the device; the removal revokes any pending or active sharing, leaving no device instance and no permissions for user2. |
| s6 | User1 removed the initial device and re-added it as a new (second) instance without re-initiating sharing; user2 has no permissions. |
| s7 | User1 re-added the device as a new (second) instance and initiated a new sharing invitation; user2 is invited but has not yet accepted the share. |
| s8 | User1 re-added the device as a new (second) instance, re-initiated sharing, and user2 accepted the invitation, granting user2 temporary direct control over the active device instance. |
