# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no invitation sent; user2 has no permissions. |
| s1 | user1 added the device once; no invitation was issued, so user2 has no access or control rights. |
| s2 | Error state. |
| s3 | user1 added a device once and sent a family invitation; user2 is invited but has not yet accepted. |
| s4 | user1 sent an invitation without adding a device; user2’s invitation remains pending and no device is bound. |
| s5 | user1 added the device once and sent an invitation; user2 scanned the QR code to initiate acceptance but has not confirmed acceptance, leaving sharing pending. |
| s6 | user1 added the device once and sent an invitation; user2 scanned and accepted the invitation, thereby becoming a family member with permanent control rights. |
| s7 | user1 added the device once and sent two invitations; user2 scanned and accepted the second invitation, thereby becoming a family member with permanent control rights. |
| s8 | user1 sent an invitation without adding a device; user2 scanned and accepted the invitation, thereby establishing family membership with control rights. |
| s9 | user1 sent multiple invitations without adding a device; user2 scanned and accepted an invitation, thereby becoming a family member with permanent control rights. |
| s10 | user1 sent an invitation without adding a device; user2 scanned the QR code but did not accept, leaving the invitation pending. |
| s11 | user1 added the device once and sent an invitation; user2 scanned and accepted to gain family membership but then quit home, which revokes user2’s control rights. |
| s12 | user1 sent an invitation without adding a device; user2 scanned and accepted the invitation, but then quit home, resulting in the revocation of family membership and control rights. |
| s13 | user1 sent an invitation and user2 scanned the QR code; subsequently, user1 re-sent an invitation without a follow-up acceptance, leaving user2 in a pending state with no granted permissions. |
| s14 | user1 added the device once and sent two invitations; user2 scanned the QR code but did not accept either invitation, so the invitation remains pending and control is not granted. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state; no device has been added and no invitation has been issued, so user2 has no permissions. |
| s1 | User1 has added one device (device count = 1) with no invitation sent; user2 remains uninvited and without access. |
| s2 | Error state. |
| s3 | User1 sent a family invitation without adding a device; user2 has not taken any action regarding the invitation. |
| s4 | User1 sent a family invitation (without adding a device) and user2 scanned the QR code, but acceptance is still pending. |
| s5 | User1 sent a family invitation (with no device added) that was accepted by user2, establishing user2 as a permanent family member with control rights. |
| s6 | User1 issued two invitations (with no device added) and user2 accepted the later invitation, resulting in the establishment of permanent family membership. |
| s7 | User1 added one device and then issued invitations that were accepted by user2; as a result, user2 becomes a permanent family member with control rights. |
| s8 | User1 added one device and sent a family invitation that was scanned and accepted by user2, thereby granting permanent family control over the device. |
| s9 | User1 sent an invitation without adding a device; user2 accepted the invitation and then quit home—although the active control ceased, family membership (and thus permission) persists. |
| s10 | User1 added one device and sent an invitation; user2 only scanned the QR code without accepting, leaving the invitation pending. |
| s11 | User1 added one device and sent an invitation, but user2 has not yet responded, so no access is granted. |
| s12 | User1 added one device and sent a family invitation that was accepted by user2; although user2 later quit home, the family membership (and its associated rights) persists. |
| s13 | User1 added one device and issued multiple invitations; user2 scanned an invitation but did not finalize acceptance, leaving family membership unconfirmed. |
| s14 | Without any device added, user1 reissued an invitation and user2 scanned the QR code, but acceptance has not yet been completed. |
| s15 | User1 added one device and issued invitations that were accepted by user2, who is now actively controlling the device as a permanent family member. |
| s16 | User1 added a device and completed the invitation process; after the device was removed, user2—being a confirmed family member—retains permanent control rights for when a device is re-added. |
| s17 | User1 added a device and sent an invitation that was accepted by user2; after the device was removed, user2 subsequently quit home, ceasing active control though family membership remains intact. |
| s18 | User1 added a device, then removed it and re-added it (resulting in one active instance); user2 accepted the invitation and controlled the device but later quit home, so active control is lost while family membership persists. |
| s19 | User1 added one device and sent a family invitation that was accepted by user2; although user2 controlled the device and later quit home, the permanent family permissions remain. |
| s20 | User1 added one device and completed the invitation process; user2 accepted and controlled the device, then quit home and later scanned the QR code attempting to rejoin—however, without re-acceptance active control is not restored. |
| s21 | User1 added a device, removed it, and re-added it (yielding one active instance) after invitation acceptance; user2, having quit home after initial control, is scanning the QR code with rejoining pending acceptance. |
| s22 | User1 added a device which was later removed (leaving no active instance); user2 had accepted and controlled the device but then quit home and is now scanning the QR code, with re-acceptance pending. |
| s23 | User1 added a device that was later removed and then sent a new invitation; user2—previously a family member who quit home—scanned the new invitation but has not yet accepted, leaving membership pending reactivation. |
| s24 | User1 added a device, removed it, re-added it (resulting in one active instance), and reissued an invitation; user2, previously a family member who quit home, scanned the new QR code but has not re-accepted, so active control is pending reactivation. |
| s25 | User1 added one device and engaged in multiple invitation rounds; although user2 was a family member and had controlled the device, after quitting home the latest QR scan leaves re-acceptance pending for active control. |
| s26 | User1 added a device that was later removed (resulting in no active instance); because user2 accepted the invitation and controlled the device before removal, user2 remains a permanent family member with rights despite the absence of an active device. |
| s27 | User1 added a device that was subsequently removed; user2 accepted the invitation and controlled the device before quitting home, thereby retaining permanent family membership though active control is lost. |
| s28 | User1 added a device, then removed it and re-added it (resulting in one active instance); user2 accepted the invitation and controlled the device but later quit home, so active control is no longer exercised while family membership persists. |
| s29 | User1 added a device, removed it, and re-added it (yielding one active instance); user2 accepted the invitation as a confirmed family member and continues to actively control the device. |
| s30 | User1 added one device and sent an invitation that was accepted by user2, who is now actively controlling the device as a permanent family member. |
| s31 | User1 added one device and sent an invitation that was accepted by user2; although user2 subsequently quit home, family membership persists while active control is suspended. |
| s32 | User1 added a device, then removed it and re-added it (resulting in one active instance) after a successful invitation process; user2 remains a permanent family member and continues to actively control the device. |

