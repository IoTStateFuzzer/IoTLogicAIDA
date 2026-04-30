# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state. |
| s1 | user1 added the device once (device count = 1) without sending any invitation; user2 has not been invited and therefore has no permissions. |
| s2 | Error state. |
| s3 | user1 added the device once and issued a family invitation; user2 has been invited but has not yet accepted, so no control rights are granted. |
| s4 | user1 issued a family invitation without adding a device; the invitation remains pending and user2 has no control rights. |
| s5 | user1 added the device once and sent a family invitation; user2 scanned the QR code but has not accepted the invitation, leaving family membership (and control permissions) pending. |
| s6 | user1 added the device once and sent a family invitation; user2 scanned and accepted the invitation, thereby becoming a family member with permanent control rights regardless of future device state. |
| s7 | user1 added the device once and issued two family invitations; user2 eventually accepted one of them, establishing permanent family membership with control rights. |
| s8 | user1 issued a family invitation without adding a device; user2 scanned and accepted the invitation, thereby becoming a family member with permanent control rights applicable to any subsequently added device. |
| s9 | user1 sent two family invitations without adding a device; user2 scanned and accepted one of them, thereby gaining permanent family membership and control rights despite no device being added. |
| s10 | user1 issued a family invitation; user2 scanned the QR code but did not accept, so the invitation remains pending and no control rights are granted. |
| s11 | user1 added the device once and sent a family invitation; user2 scanned and accepted the invitation but later quit family membership, which revoked the control rights. |
| s12 | user1 issued a family invitation without adding a device; user2 scanned and accepted the invitation, becoming a family member, but later quit, thereby revoking control rights. |
| s13 | user1 issued two family invitations without adding a device; user2 scanned the QR code on the invitations but did not accept any, leaving the invitation pending with no permissions granted. |
| s14 | user1 added the device once and sent two family invitations; user2 scanned the QR code but did not accept, so no control rights are granted and the invitation remains pending. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state; no device has been added and no invitation has been issued. |
| s1 | User1 added one device instance (device count = 1) without issuing any invitation; user2 has no permissions. |
| s2 | Error state. |
| s3 | User1 initiated an invitation (InviteToHome) without adding a device; user2 has not scanned or accepted the invitation, so no permissions are granted. |
| s4 | User1 sent an invitation and user2 scanned the QR code to begin the acceptance process; however, the invitation remains unaccepted and no control is granted. |
| s5 | User1 issued an invitation that user2 both scanned and accepted, making user2 a family member with permanent control—even though no device was added. |
| s6 | User1 issued two consecutive invitations (with no device addition), and user2 scanned and accepted the later invitation, thereby becoming a family member with permanent control rights. |
| s7 | User1 added the device (device count = 1) and issued multiple invitations; user2 scanned and accepted one of them, resulting in family membership with enduring control over the device. |
| s8 | User1 added the device (device count = 1) and completed the invitation flow when user2 scanned and accepted the invitation, which grants permanent family membership and control. |
| s9 | User1 issued an invitation that was accepted by user2, but later user2 quit the home; as a result, family membership and control were terminated. |
| s10 | User1 added the device (device count = 1) and sent an invitation; user2 scanned the QR code but has not yet accepted the invitation, so no control is granted. |
| s11 | User1 added the device (device count = 1) and issued an invitation, but user2 neither scanned nor accepted it, leaving permissions ungranted. |
| s12 | User1 added the device (device count = 1) and invited user2; although user2 scanned and accepted the invitation (gaining family membership), user2 later quit home, thereby revoking membership and control. |
| s13 | User1 added the device (device count = 1) and sent multiple invitations; user2 scanned one invitation but did not complete the acceptance process, so the invitation remains pending with no control granted. |
| s14 | User1 sent multiple invitations (including at least one QR scan) but user2 did not accept any; as a result, the invitation remains pending and no control is granted. |
| s15 | User1 added the device (device count = 1) and issued multiple invitations; user2 scanned and accepted the invitation, thereby becoming a family member with active control rights. |
| s16 | User1 added the device (device count = 1) and invited user2; after user2 scanned, accepted, and controlled the device, user1 removed the device—but since user2 is a family member, permanent control rights are retained. |
| s17 | User1 added the device (device count = 1) and invited user2; after user2 scanned, accepted, and controlled the device, user1 removed the device and user2 subsequently quit home, which terminated family membership and control. |
| s18 | User1 added the device, then removed and re-added it (final count = 1), while having issued invitations; user2 scanned and accepted (gaining control), but later quit home, thereby revoking family membership and control. |
| s19 | User1 added the device (device count = 1) and invited user2; user2 scanned, accepted, and controlled the device, but later quit home—thus terminating family membership and control rights. |
| s20 | User1 added the device (device count = 1) and invited user2; after user2 scanned, accepted, and controlled the device, user2 quit home and later scanned the QR code again without accepting the new invitation, leaving no active membership or control. |
| s21 | User1 added the device (after removal and re-addition, final count = 1) and invited user2; user2 scanned and accepted to control the device, but after quitting home and scanning again, the new invitation remains unaccepted, so no active control is present. |
| s22 | User1 added the device (device count = 1) and invited user2; although user2 scanned, accepted, and initially controlled the device, a subsequent device removal combined with user2 quitting (followed by a QR scan) left the latest invitation pending and no active control. |
| s23 | User1 added the device (device count = 1) and invited user2; even if user2 had previously accepted, a later sequence (rescan and a new invitation after quitting) went unaccepted, so user2 is not a family member and has no control. |
| s24 | User1 added the device (with a net final count = 1) and, after a removal, sent a fresh invitation following user2’s quit; since user2 has not accepted the new invitation, no control is granted. |
| s25 | User1 added the device (device count = 1) and invited user2; although user2 scanned, accepted, and exercised control initially, user2 later quit home and a subsequent invitation remains unaccepted, resulting in no active control. |
| s26 | User1 added the device (device count = 1) and invited user2; user2 scanned, accepted, and controlled the device, and even though user1 later removed the device, family membership ensures that user2 retains permanent control rights. |
| s27 | User1 added the device (device count = 1) and invited user2; after user2 scanned, accepted, and controlled the device, user1 removed the device and user2 subsequently quit home, which terminated the family membership and revoked control. |
| s28 | User1 added the device (removed and then re-added, with final count = 1) and invited user2; user2 scanned, accepted, and controlled the device, but later quit home, thereby revoking family membership and control. |
| s29 | User1 added the device, then removed and re-added it (final count = 1) without issuing a new invitation; since user2 had previously scanned and accepted the invitation, family membership persists and user2 retains control rights. |
| s30 | User1 added the device (device count = 1) and invited user2; user2 scanned and accepted the invitation, thereby obtaining active family membership with control over the device. |
| s31 | User1 added the device (device count = 1) and invited user2; although user2 scanned, accepted, and controlled the device, user2 later quit home, resulting in the loss of family membership and control. |
| s32 | User1 added the device, issued two invitations, and then removed and re-added the device (final count = 1); user2 scanned and accepted the invitations, thereby remaining a family member with persistent control rights. |

