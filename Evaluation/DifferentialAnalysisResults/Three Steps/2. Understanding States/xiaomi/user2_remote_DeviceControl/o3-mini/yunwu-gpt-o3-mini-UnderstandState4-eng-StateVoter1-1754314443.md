# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state with no device added or sharing initiated. |
| s1    | user1 has added the device once (device addition count = 1) without initiating any sharing; user2 has not been invited and holds no permissions. |
| s2    | Error state. |
| s3    | user1 added the device (device addition count = 1) and issued a direct share invitation (via ShareCamera); user2’s acceptance is pending, so no control is granted yet. |
| s4    | user1 added the device (device addition count = 1) and shared it via direct device sharing; user2 accepted the invitation and now holds direct control for that device instance (revocable upon device removal). |
| s5    | user1 added and shared the device but then removed it, which revokes any active or pending direct sharing; consequently, user2 loses permission over the device. |
| s6    | user1 removed the device and then re-added it (device addition count = 2), creating a new device instance without a re-initiated share; user2 holds no permissions on this new instance. |
| s7    | user1 re-added the device (device addition count = 2) and issued a new direct share invitation; user2 is invited but has not yet accepted, so no control is granted. |
| s8    | user1 re-added the device (device addition count = 2) and re-initiated direct sharing; user2 accepted the invitation and now holds direct control over the current device instance (revocable upon removal). |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device has been added and no sharing invitation or permissions have been initiated. |
| s1 | user1 added the device (device addition count = 1) without initiating any share; user2 has no permission. |
| s2 | Error state. |
| s3 | user1 added the device (count = 1) and initiated a share invitation; user2 is invited but has not yet accepted. |
| s4 | user1’s device (count = 1) is shared and the invitation has been accepted, granting user2 direct control permission over that instance. |
| s5 | user1 added the device (count = 1) and sent a share invitation but then removed the device—this revokes any pending or active share and leaves no active device instance, so user2 has no permission. |
| s6 | After removal, user1 re-added the device (device addition count becomes 2) without reissuing a share invitation; user2 consequently has no permission. |
| s7 | With the re-added device (count = 2), user1 issues a new share invitation; user2 is invited but has not yet accepted. |
| s8 | For the re-added device (count = 2), the share invitation is accepted, and user2 now holds direct control permission on that instance. |
| s9 | user1 added the device (count = 1) and shared it, with user2 accepting the invitation and actively controlling the device. |
| s10 | After user2 had gained control of the device (count = 1), user1 removed the device, thereby revoking user2’s control permission as the active instance is lost. |
| s11 | user1 re-added the device after removal (device addition count becomes 2) without reinitiating sharing; as a result, the previously accepted share does not carry over and user2 has no permission. |
| s12 | user1’s device (count = 1) was shared and accepted—granting user2 control—but then user1 unshared the device, which revokes user2’s permission while the device remains active. |
| s13 | With the device still active (count = 1), user1 re-initiated sharing, so a new share invitation is pending and user2 has no current permission until acceptance. |
| s14 | user1 initially shared the device (count = 1) with accepted control by user2, then removed it and re-added a new instance (count becomes 2) with a new share invitation; the earlier permission does not carry over, leaving user2 invited but pending acceptance. |
| s15 | user1’s device was shared and accepted (user2 in control), then unshared and re-shared, but subsequently the device was removed—leaving no active device instance and revoking user2’s permission. |
| s16 | Following the removal in the previous state, user1 re-added the device (count = 2) without issuing a share invitation; therefore, user2 has no permission. |
| s17 | user1 re-added the device (count = 2) and issued a new share invitation; user2 is invited but has not yet accepted. |
| s18 | On the re-added device (count = 2), the share invitation has been accepted, so user2 now holds direct control permission on the active instance. |
| s19 | user1 added a device, shared it, then removed that instance and re-added a new instance (count = 2) which was shared and accepted; user2 is actively controlling this latest instance. |
| s20 | Starting from an active control state (count = 2) as user2 was in control, user1 unshared the device—thereby revoking user2’s permission while the device remains active. |
| s21 | With the active device still present (count = 2) after an unshare, user1 issued a new share invitation; user2 is now invited but has not yet accepted. |
| s22 | user1 earlier shared a device (accepted and controlled) then removed that instance; after re-adding a new instance (count = 2) and re-sharing it, user2 accepted the invitation and now holds direct control on the active current instance. |
