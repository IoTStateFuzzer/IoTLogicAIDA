# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no invitation or sharing action initiated by user1; user2 has no permissions. |
| s1 | user1 added one device (device count = 1) and did not send an invitation, so user2 has no access. |
| s2 | Error state. |
| s3 | user1 added one device (device count = 1) and sent an invitation; user2 is invited but has not taken any action (no QR scan or acceptance), leaving the invitation pending. |
| s4 | user1 issued a family invitation without adding a device; user2 is invited and pending acceptance, with no device instance registered. |
| s5 | user1 added one device (device count = 1) and sent an invitation; user2 scanned the QR code—indicating intent—but has not yet accepted the invitation, so access remains pending. |
| s6 | user1 added one device (device count = 1) and sent an invitation; user2 scanned the QR code and accepted the invitation, thereby becoming a family member with permanent control rights. |
| s7 | user1 added one device (device count = 1) and sent two invitations; user2 scanned the QR code and accepted the latter invitation, establishing permanent family membership with control rights. |
| s8 | user1 issued an invitation without adding a device; user2 scanned and accepted it, becoming a family member whose permanent control rights will apply when a device is later added. |
| s9 | user1 issued multiple invitations without a device addition; user2 scanned and accepted one of them, confirming family membership and ensuring permanent control rights upon any future device addition. |
| s10 | user1 issued an invitation and user2 scanned the QR code, but without acceptance the invitation remains pending and no device has been added. |
| s11 | user1 added one device (device count = 1) and sent an invitation; user2 accepted (becoming a family member) but later quit, thereby revoking control rights. |
| s12 | user1 issued an invitation without adding a device; user2 accepted (gaining temporary family membership) but then quit, resulting in the revocation of control rights. |
| s13 | user1 sent an invitation which was scanned by user2, followed by a subsequent invitation without an accompanying acceptance; as a result, user2 remains without active control. |
| s14 | user1 added one device (device count = 1) and sent an invitation; although user2 scanned the QR code, a reissued invitation remained unaccepted, leaving user2’s control permission pending. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state with no device added and no invitation sent. |
| s1 | user1 added the device once (device count = 1) with no invitation initiated; user2 has no access. |
| s2 | Error state. |
| s3 | user1 sent an invitation (InviteToHome) without adding a device; no interaction has occurred from user2, so the invitation remains pending. |
| s4 | user1 sent an invitation and user2 scanned the QR code, but acceptance has not occurred; the sharing process remains pending. |
| s5 | user1 sent an invitation that was scanned and accepted by user2, making user2 a family member with permanent control rights—even though no device was added. |
| s6 | user1 issued a repeated invitation (a second invite following an initial scan) which user2 accepted, establishing user2 as a family member with permanent control rights without any device added. |
| s7 | user1 added the device (device count = 1) and sent an invitation (or re‐invite) that was eventually accepted; user2 becomes a family member with permanent, enduring control rights. |
| s8 | user1 added one device and completed the invitation process (invite, scan, and acceptance), thereby establishing user2 as a family member with permanent control rights. |
| s9 | user1 sent an invitation that user2 scanned and accepted, but then user2 quit home, resulting in the revocation of control rights. |
| s10 | user1 added the device (device count = 1) and sent an invitation that reached the QR scan stage but was not accepted; user2’s permission remains pending. |
| s11 | user1 added the device (device count = 1) and sent an invitation without any QR scan or subsequent acceptance; user2’s status remains pending. |
| s12 | user1 added the device (device count = 1) and completed the invitation process, but user2 later quit home, causing the control rights to be revoked. |
| s13 | user1 added the device (device count = 1) and initiated a repeated invitation after an initial QR scan, but without a subsequent acceptance; user2 remains pending. |
| s14 | Without adding a device, user1 sent an invitation that was scanned and then re‐issued; user2 remains pending acceptance. |
| s15 | user1 added the device (device count = 1) and completed the invitation process, with user2 accepting and exercising control; user2 is an active family member with permanent rights. |
| s16 | user1 added the device (device count = 1) and shared it with user2 (invitation accepted), then removed the device; however, as a family member, user2 retains permanent control rights. |
| s17 | user1 added the device (device count = 1) and completed sharing (invitation accepted and control exercised), but then removed the device and user2 quit, resulting in the loss of control rights. |
| s18 | user1 added the device, then removed it and re‐added a new instance (device count = 1); although user2 had previously accepted the invitation, a subsequent quit revokes control rights. |
| s19 | user1 added the device (device count = 1) and completed the invitation process with user2 exercising control, but afterwards user2 quit home, causing a loss of permission. |
| s20 | user1 added the device (device count = 1) and shared it (invitation accepted and control exercised), but after user2 quit, a subsequent QR scan initiated a new invitation, leaving user2 pending re‐acceptance. |
| s21 | user1 added the device, then removed and re‐added it (device count = 1); after user2 initially accepted but later quit, a subsequent QR scan triggered a new invitation, leaving user2 pending acceptance. |
| s22 | user1’s device was removed (device count = 0) and, following user2’s quit and a new QR scan, a fresh invitation was initiated; user2 remains pending acceptance. |
| s23 | user1’s device is not active and, after user2 quit, a new invitation was issued following a QR scan; user2 remains pending acceptance. |
| s24 | user1 re‐added the device (device count = 1) after removal and issued a new invitation post user2’s quit; after a QR scan, user2’s status remains pending acceptance. |
| s25 | user1 has a single device instance (device count = 1) and, after user2 quit, a subsequent QR scan re‐initiated the invitation, leaving user2 pending acceptance with no active control. |
| s26 | user1 added the device (device count = 1) and completed sharing with user2 (invitation accepted); later the device was removed, yet user2, as a family member, retains permanent control rights. |
| s27 | user1 added the device (device count = 1) and shared it (invitation accepted), but after the device was removed and user2 quit, control rights were lost. |
| s28 | user1 re‐added the device after removal (device count = 1), but even though user2 had previously accepted the invitation, a subsequent quit caused the loss of control rights. |
| s29 | user1 added the device, then removed and re‐added it (device count = 1); since user2 did not quit, user2 remains a family member with permanent control rights. |
| s30 | user1 added the device (device count = 1) and fully completed the invitation process, with user2 accepting and exercising control; user2 holds permanent, family-based control rights. |
| s31 | user1 added the device (device count = 1) and completed sharing with user2, but following a QuitHome event, user2 lost control rights. |
| s32 | user1 added the device, sent a repeated invitation that was accepted, then removed and re‐added the device (final device count = 1); as a result, user2 remains a family member with permanent control rights. |

