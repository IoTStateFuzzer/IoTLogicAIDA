# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state. |
| s1    | user1 has added the device once with no sharing initiated; user2 is neither invited nor granted any permissions. |
| s2    | Error state. |
| s3    | user1 has added the device (device count = 1) and initiated a sharing invitation; user2 is invited and pending manual acceptance, so no control rights are granted yet. |
| s4    | user1 has added the device (device count = 1) and issued a sharing invitation, which user2 accepted, granting direct control rights limited to the current device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device has been added and no sharing or control actions have been executed. |
| s1 | user1 added the device once (instance count = 1) without initiating any sharing; user2 has no invitation or permissions. |
| s2 | Error state. |
| s3 | user1 added the device and initiated a sharing invitation (via SharePlug); user2 is pending acceptance and holds no control permissions. |
| s4 | user1 added the device and shared it; user2 accepted the invitation, thereby gaining temporary direct control rights for the current device instance. |
| s5 | user1’s device remains added and shared; user2, having accepted the sharing invitation, is actively exercising device control under temporary direct sharing permission. |
| s6 | user1 unshared the device (via UnsharePlug), revoking user2’s previously accepted direct sharing permission while the device remains added. |
| s7 | user1 reinitiated sharing by issuing a new invitation; user2’s prior accepted control is revoked, and user2 is now pending acceptance of the new invitation. |
| s8 | user1 removed the device instance; removal terminates the device instance and revokes any active or pending direct sharing permissions for user2. |

