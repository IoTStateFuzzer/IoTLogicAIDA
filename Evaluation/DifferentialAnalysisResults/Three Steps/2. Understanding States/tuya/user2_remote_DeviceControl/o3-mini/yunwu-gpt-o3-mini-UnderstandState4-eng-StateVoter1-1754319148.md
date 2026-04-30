# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state. |
| s1 | User1 has added the device once (device addition count = 1) with no sharing action performed; user2 has no permissions. |
| s2 | Error state. |
| s3 | User1 added the device once and then executed a direct sharing action ("SharePlug"), granting user2 direct control rights over this specific device instance. This non-family permission will be revoked if the device is removed and re-added. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state |
| s1 | user1 added the device once; no sharing was initiated, so user2 has no permissions. |
| s2 | Error state |
| s3 | user1 added the device and initiated direct device sharing (SharePlug), which—via automatic acceptance—grants user2 direct permission for that specific device instance (even though user2 has not yet exercised control). |
| s4 | With the device instance actively shared via direct sharing, user2 exercised DeviceControl, confirming that the direct sharing permission is active for that specific instance. |
| s5 | After sharing and device control, user1 revoked sharing (UnsharePlug), thereby terminating user2’s direct permission while the device remains added. |
| s6 | user1 removed the device instance after sharing and device control; removal revokes user2’s direct sharing permission and clears the device addition for that instance. |
