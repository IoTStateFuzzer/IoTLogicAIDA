# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no sharing initiated. |
| s1 | user1 has added the device once (device instance count = 1) without issuing any sharing invitation; user2 has no permission. |
| s2 | Error state. |
| s3 | user1 added the device (first addition) and initiated a direct sharing invitation (e.g., via ShareCamera); user2 is pending acceptance and does not have control rights until acceptance. |
| s4 | user1’s first device instance is active and the sharing invitation has been accepted by user2, granting them direct control rights for that instance. |
| s5 | user1 added and shared the device, then removed it; the removal revokes any pending or granted sharing permissions, leaving no active device instance and revoking user2’s control rights. |
| s6 | user1 removed the initially shared device and re-added a new instance (device count becomes 2) without re-initiating sharing; consequently, user2’s previous permission does not carry over. |
| s7 | For the second device instance, user1 re-initiated sharing by sending a new invitation; user2 has not yet accepted, so no control rights are granted. |
| s8 | user1’s second device instance is active with a re-initiated sharing invitation that user2 accepted, thereby granting direct control rights for the current device instance. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device has been added and no sharing invitation or permission exists for user2. |
| s1 | User1 has added one device instance (addition count = 1) without initiating any sharing; user2 therefore has no invitation or access. |
| s2 | Error state. |
| s3 | User1 added the device (addition count = 1) and initiated a ShareCamera invitation; user2 is invited but has not yet accepted the share. |
| s4 | User1’s device (addition count = 1) is shared and the invitation has been accepted, granting user2 direct control over that instance. |
| s5 | User1 added the device and initiated sharing, then removed the device instance; as a result, any pending or accepted permission for user2 is cancelled. |
| s6 | After removal of the previous instance, user1 re-added the device (addition count = 2) without issuing a new sharing invitation; user2 has no access. |
| s7 | User1 re-added the device (addition count = 2) and initiated sharing on the new instance; user2 is invited but has not yet accepted the invitation. |
| s8 | User1’s second device instance (addition count = 2) is shared and the invitation has been accepted, thereby granting user2 direct control over that instance. |
| s9 | User1 added the device (addition count = 1) and shared it; user2 accepted the share and exercised device control on that instance. |
| s10 | After the device (addition count = 1) was added, shared, accepted, and controlled by user2, user1 removed the device—thereby revoking user2’s permission. |
| s11 | User1 removed the shared device and then re-added a new instance (addition count = 2) without re-initiating sharing; consequently, user2 loses any previous access. |
| s12 | User1’s device (addition count = 1) was shared, accepted, and under user2’s control, but then user1 unshared it; this unsharing revokes user2’s permission while the device remains added. |
| s13 | After unsharing a device with an accepted share, user1 re-initiated sharing on the same instance (addition count = 1), so user2 now has a pending invitation and no active control. |
| s14 | User1 initially shared an instance (instance 1) that was accepted by user2, but after removal that permission was lost; upon re-adding (addition count = 2) and issuing a fresh share invitation, user2 must re-accept to gain control. |
| s15 | User1’s device was shared and accepted (granting user2 control) but then unshared and re-shared prior to removal; the subsequent removal cancels the current pending share so that user2 ends without access. |
| s16 | Following a cycle where sharing was revoked and re-initiated on the first instance, user1 removed the device and re-added a new instance (addition count = 2); user2’s permission from the removed instance does not carry over to the new one. |
| s17 | User1 re-added the device (addition count = 2) after removal and re-initiated sharing; user2 is invited for the new instance but has not yet accepted the share. |
| s18 | User1’s re-added device instance (addition count = 2) is shared and the invitation has been accepted, thereby granting user2 active direct control over the current instance. |
| s19 | User1 removed the initial device instance then re-added a new one (addition count = 2) that was shared and accepted; user2 is actively controlling the new instance. |
| s20 | On the new device instance (addition count = 2) that was shared and accepted (granting user2 control), user1 later unshared the device, revoking user2’s permission while keeping the device bound. |
| s21 | After unsharing the current instance, user1 re-initiated sharing on the same device (addition count = 2); this revokes the previous control and leaves a new pending invitation for user2. |
| s22 | User1 initially shared a device (instance 1) that was accepted and controlled by user2, but after its removal, user1 re-added a new instance (addition count = 2) and shared it; upon acceptance, user2 gains active control on the current instance while the old permission is revoked. |
