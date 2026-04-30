# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no sharing invitation or action initiated. |
| s1 | user1 has added the device once (device addition count = 1) without initiating any sharing; user2 has no invitations or permissions. |
| s2 | Error state. |
| s3 | user1 has added the device (first instance) and issued a sharing invitation (direct device sharing); user2 is invited but has not yet accepted, so no control rights are granted. |
| s4 | user1 has added the device (first instance) and completed a sharing action by having user2 accept the invitation; user2 now holds direct control rights for that device instance (subject to revocation upon removal/re-addition). |
| s5 | user1 added and shared the device (first instance) and then removed it, which revokes any pending or accepted direct sharing; consequently, user2 loses control permissions. |
| s6 | user1 removed the initial device and re-added it (device addition count increases to 2) without issuing a new sharing invitation; therefore, user2 holds no permissions on the newly added device instance. |
| s7 | user1 re-added the device (second instance, count = 2) and issued a new sharing invitation; user2 is invited but has not yet accepted, so no control rights are granted. |
| s8 | user1 re-added the device (second instance, count = 2) and re-initiated sharing, which user2 accepted, thereby granting direct control rights for the current device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device instance has been added and no sharing initiated; user2 holds no invitation or permission. |
| s1 | user1 added the device for the first instance; no share invitation was issued, so user2 has no permission. |
| s2 | Error state. |
| s3 | user1 added the device and initiated a share invitation on that instance; user2 is invited but has not yet accepted. |
| s4 | user1’s first device instance is active and shared, and user2 accepted the share invitation—granting control over that instance. |
| s5 | user1 added and shared the device but then removed the device instance; the removal revokes any pending or accepted share, leaving no active device for user2. |
| s6 | After removal, user1 re-added a new device instance without issuing a new share invitation; user2 has no permission on the new instance. |
| s7 | user1 re-added the device instance and initiated a new share invitation; user2 is invited for the current instance but has not yet accepted. |
| s8 | user1’s current device instance is active and shared, and user2 accepted the invitation—thus gaining control over this instance. |
| s9 | user1 added and shared the device, with user2 accepting the share invitation and actively controlling the device instance. |
| s10 | After the device was shared, accepted, and under user2’s control, user1 removed the device instance, which revokes user2’s permission. |
| s11 | Following removal, user1 re-added a new device instance without re-sharing; since sharing doesn't persist across removals, user2 loses permission. |
| s12 | user1’s device instance was shared and accepted by user2, but a subsequent unshare action revoked the permission—even though the device remains active. |
| s13 | After unsharing the previously accepted share on the active device instance, user1 re-initiated sharing, leaving user2 with a pending invitation requiring re-acceptance. |
| s14 | user1 removed the initially shared device instance and then re-added a new instance with a fresh share invitation; user2 is invited but has not yet accepted. |
| s15 | On an active device instance, user1 unshared then re-shared the device but eventually removed it, resulting in no active device instance and revoking user2’s permission. |
| s16 | After removal, user1 re-added a new device instance without a share invitation; consequently, user2 has no invitation or permission on this instance. |
| s17 | user1 added a new device instance and initiated a share invitation; user2 is invited but has not accepted the invitation yet. |
| s18 | user1’s current device instance is active and shared with an accepted invitation, thereby granting user2 direct control over that instance. |
| s19 | user1 initially added and shared a device instance but removed it, then re-added a new instance that was shared and accepted—granting user2 control over the current (second) instance. |
| s20 | user1’s active device instance was shared and accepted (with user2 controlling it), but a subsequent unshare revoked user2’s permission while the device remains active. |
| s21 | Following an unshare that revoked active permission, user1 re-initiated sharing on the active device instance, leaving user2 with a pending invitation requiring re-acceptance. |
| s22 | user1 initially shared a device instance and had it accepted, then removed that instance and re-added a new one that was shared and accepted; thus, user2 holds control only on the most recent active instance. |
