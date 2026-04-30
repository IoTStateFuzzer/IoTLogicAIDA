# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state; no device has been added and no sharing activity has occurred. |
| s1 | user1 added the device for the 1st instance without initiating any sharing invitation; user2 has no permissions. |
| s2 | Error state. |
| s3 | user1 added the device and issued a direct sharing invitation; user2 is invited but has not yet accepted, so no control is granted. |
| s4 | user1 added the device (1st instance) and initiated direct device sharing, which user2 accepted, granting control over that instance. |
| s5 | user1 added the device and initiated sharing, then removed the device instance; removal cancels the active or pending sharing, leaving user2 with no permission. |
| s6 | user1 re-added the device (now the 2nd instance) without re-initiating a new share; the previous sharing is invalidated, so user2 has no active permission. |
| s7 | user1 re-added the device (2nd instance) and issued a new direct sharing invitation; user2 is invited but has not yet accepted, so control remains unassigned. |
| s8 | user1 re-added the device (2nd instance), initiated sharing, and user2 accepted the invitation, thereby granting direct control for the current instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added or sharing initiated. |
| s1 | user1 added the device once (first addition) without issuing any sharing invitation; user2 holds no permissions. |
| s2 | Error state due to an invalid operation or sequence. |
| s3 | user1 added the device once and issued a share invitation (direct device sharing), leaving user2 with a pending invitation and no control rights until acceptance. |
| s4 | user1 added the device once and shared it; user2 accepted the invitation, thereby gaining direct control rights for that specific device instance. |
| s5 | user1 added and shared the device then removed it; the removal revokes the direct sharing permission, so user2 loses all control rights. |
| s6 | user1 re-added the device (second addition) after removal without reissuing a share invitation; as a result, user2 does not receive any active permission. |
| s7 | user1 re-added the device and sent a new share invitation; user2 is invited for the current device instance, but control rights are pending acceptance. |
| s8 | user1 re-added the device and re-initiated sharing; following user2’s acceptance of the invitation, control rights are granted for the current (second) device instance. |
