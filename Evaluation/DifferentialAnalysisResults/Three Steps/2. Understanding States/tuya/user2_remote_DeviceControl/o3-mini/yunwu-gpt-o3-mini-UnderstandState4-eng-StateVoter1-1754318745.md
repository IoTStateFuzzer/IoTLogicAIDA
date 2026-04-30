# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state |
| s1    | User1 has added the device once (device addition count = 1) with no sharing action initiated; user2 remains without any control rights. |
| s2    | Error state |
| s3    | User1 added the device once and then executed a sharing action using direct device sharing, granting user2 control rights for that specific device instance; these permissions are revoked if the device is removed and re-added. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state. |
| s1    | user1 has added the device once without initiating any sharing; therefore, user2 does not have any access permissions. |
| s2    | Error state. |
| s3    | user1 added the device and initiated direct sharing (via SharePlug) for the current instance, automatically granting user2 direct control permission. |
| s4    | user1’s device instance is shared and user2 has exercised remote control, confirming that the active direct sharing permission applies only to the current device instance. |
| s5    | user1 added and shared the device and user2 exercised control; subsequently, user1 revoked sharing (via UnsharePlug), thereby removing user2’s direct control permission while the device remains added. |
| s6    | user1 added and shared the device and user2 exercised control; thereafter, user1 removed the device, which revokes the direct sharing permission and leaves no active device instance. |
