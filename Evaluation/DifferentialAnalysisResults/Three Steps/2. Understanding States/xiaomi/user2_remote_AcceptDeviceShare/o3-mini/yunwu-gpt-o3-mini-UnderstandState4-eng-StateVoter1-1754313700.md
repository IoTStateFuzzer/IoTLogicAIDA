# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added or sharing initiated. |
| s1 | user1 added the device (first instance) without initiating any sharing invitation; user2 holds no invitation or control permission. |
| s2 | Error state. |
| s3 | user1 added the device (first instance) and issued a direct sharing invitation; user2 has been invited but has not yet accepted, so no control is granted. |
| s4 | user1 added and directly shared the device (first instance); user2 accepted the invitation, thereby acquiring control rights for that specific device instance (control is revoked if the device is removed). |
| s5 | user1 added and shared the device, then removed it, which revokes the direct sharing privileges; as a result, user2 holds no permission. |
| s6 | Following device removal, user1 re-added the device (second instance) without issuing a new sharing invitation; user2 does not hold any control rights. |
| s7 | user1 re-added the device (second instance) and issued a new direct sharing invitation; user2 is invited but has not yet accepted, so control remains unassigned. |
| s8 | user1 re-added the device (second instance), re-initiated the direct sharing invitation, and user2 accepted; this grants user2 control rights for the current device instance. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state with no device added and no sharing actions performed. |
| s1 | user1 has added the device for the first time (instance 1) with no sharing invitation issued; user2 holds no permissions. |
| s2 | Error state. |
| s3 | user1 added the device (instance 1) and initiated a direct sharing invitation (via ShareCamera); user2’s invitation remains pending with no control rights granted. |
| s4 | user1 added the device (instance 1), initiated a direct sharing invitation, and user2 accepted it—granting control permission for that specific device instance. |
| s5 | user1 added the device and initiated sharing but then removed the device instance, which revokes the pending sharing invitation; no active device instance or user2 permissions remain. |
| s6 | After removing the first instance, user1 re-added the device (instance 2) without initiating a new sharing invitation; user2 holds no permissions for the second instance. |
| s7 | user1 re-added the device (instance 2) and initiated a direct sharing invitation; user2’s invitation for the new instance is pending acceptance with no control rights yet. |
| s8 | user1 re-added the device (instance 2), re-initiated sharing, and user2 accepted the invitation—granting direct control permission solely for that device instance. |
