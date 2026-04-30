# Base Model
| State | Final Semantic Description |
|-------|-----------------------------|
| s0 | Initial state: no device has been added and no sharing has been initiated. |
| s1 | User1 added the device (count = 1) without issuing any invitation; user2 remains uninvolved with no permissions. |
| s2 | Error state. |
| s3 | User1 added the device (count = 1) and issued an invitation; user2 is invited and pending acceptance. |
| s4 | User1 issued an invitation without adding a device; user2 is invited but has not completed the acceptance process. |
| s5 | User1 added the device (count = 1) and invited user2; user2 scanned the QR code to indicate intent, but acceptance is still pending and no control rights are granted. |
| s6 | User1 added the device (count = 1) and invited user2; after scanning the QR code and accepting the invitation, user2 becomes a family member with permanent control rights. |
| s7 | User1 added the device (count = 1) and issued two invitations; user2 scanned the QR code and accepted the later invitation, thereby establishing permanent family membership and control rights. |
| s8 | User1 issued an invitation without adding a device; user2 scanned and accepted the invitation, thereby becoming a family member with permanent control rights despite the absence of a device addition. |
| s9 | User1 issued repeated invitations without adding a device; user2 scanned and accepted the final invitation, resulting in family membership with permanent control rights even though no device has been added. |
| s10 | User1 sent an invitation and user2 scanned the QR code, but without subsequent acceptance, no control rights are granted. |
| s11 | User1 added the device (count = 1) and invited user2; although user2 scanned and accepted the invitation to gain permanent control, user2 later quit, thereby revoking their family membership and control rights. |
| s12 | User1 issued an invitation without adding a device; user2 scanned and accepted the invitation to gain family membership, but later quit, leading to the revocation of control rights. |
| s13 | User1 issued an invitation and user2 scanned the QR code, then a subsequent invitation was sent; however, without an accompanying acceptance, the sharing remains pending and no control rights are granted. |
| s14 | User1 added the device (count = 1) and sent invitations; user2 scanned a QR code but did not complete acceptance, so no control rights are granted. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state; no device has been added and no invitation has been sent. |
| s1 | User1 has added one device (device count = 1) without sending any invitation, so user2 has no permissions. |
| s2 | Error state. |
| s3 | User1 sent an invitation (without adding a device) and user2 has not interacted with it (no QR scan or acceptance). |
| s4 | User1 sent an invitation and user2 scanned the QR code, but acceptance is still pending; no device has been added. |
| s5 | User1 sent an invitation and user2 scanned then accepted it, thereby becoming a family member with permanent control rights; no device has been added. |
| s6 | User1 issued two invitation actions (the second following a QR scan) and user2 accepted the later invitation, establishing family membership even though no device was added. |
| s7 | User1 added one device (device count = 1) and sent invitation(s); user2 scanned and accepted one invitation, gaining perpetual family membership with control rights. |
| s8 | User1 added one device and sent an invitation that was scanned and accepted by user2; user2 now holds permanent family membership and control over the device instance. |
| s9 | User1 sent an invitation without adding a device and user2 scanned and accepted it; even though user2 later quit home, as a family member the permanent rights persist. |
| s10 | User1 added one device (device count = 1) and sent an invitation; user2 scanned the QR code but did not accept, leaving the invitation pending. |
| s11 | User1 added one device and sent an invitation; with no interaction (neither scan nor acceptance) from user2, no permissions are granted. |
| s12 | User1 added one device and sent an invitation that was scanned and accepted by user2; although user2 later quit home, family membership (and its permanent control rights) remains. |
| s13 | User1 added one device and sent invitation(s); user2 performed a QR scan on one invite but did not accept the subsequent invitation, so the invitation remains pending and no family membership is established. |
| s14 | User1 sent invitation(s) without adding a device and user2 scanned one of them; without acceptance, the invitation remains pending and user2 is not a family member. |
| s15 | User1 added one device and sent multiple invitations; user2 scanned, accepted and exercised device control, thereby becoming an active family member with permanent rights. |
| s16 | User1 added one device and sent an invitation that was scanned, accepted, and used for control by user2; even after user1 removed the device, user2’s family membership (and permanent control rights) persists. |
| s17 | User1 added a device and sent an invitation that user2 scanned, accepted, and used to control the device; then user1 removed the device and user2 quit home, but as a family member, user2’s permanent rights persist. |
| s18 | User1 added a device and invited user2, who scanned, accepted and controlled it; after user1 removed and re-added the device (final count = 1) and user2 quit home, family membership continues. |
| s19 | User1 added one device and sent an invitation that was scanned, accepted, and used for control by user2; even after user2 quit home, the family membership (and permanent control) remains intact. |
| s20 | User1 added one device and sent an invitation that user2 scanned, accepted, and used to control the device; although user2 subsequently quit home and then performed another QR scan (resulting in a pending reactivation), the family membership persists. |
| s21 | User1 added a device (after a removal and re-addition, final count = 1) and sent an invitation that was accepted and used for control by user2; despite a subsequent quit and a new QR scan by user2, family membership continues. |
| s22 | User1 added a device that was later removed (final device count = 0) and sent an invitation that user2 accepted and used for control; even after user2 quit home and scanned again, the accepted family membership remains intact. |
| s23 | User1 added a device and sent an invitation that was scanned, accepted, and used for control by user2; after user2 quit (and performed an additional scan) and user1 sent a new invitation (without re-adding a device), user2’s family membership persists. |
| s24 | User1 added a device, then removed and re-added it (final count = 1) and issued multiple invitations; user2 accepted an earlier invitation, later quit and scanned again, so family membership remains in force. |
| s25 | User1 added one device and issued multiple invitations; user2 accepted the invitation and exercised control, then quit and scanned again—maintaining permanent family membership. |
| s26 | User1 added a device and sent an invitation that was scanned and accepted by user2, granting family membership and control rights; though user1 later removed the device (device count becomes 0), user2’s permanent rights persist. |
| s27 | User1 added a device and sent an invitation that was scanned, accepted, and used for control by user2; subsequently, after user1 removed the device and user2 quit home, the family membership continues. |
| s28 | User1 added a device, removed it, and re-added it (final count = 1) while sending an invitation that user2 scanned, accepted, and used for control; although user2 later quit home, family membership remains intact. |
| s29 | User1 added a device and issued an invitation that was scanned, accepted, and used for control by user2; after a removal and re-addition of the device (final count = 1), user2’s family membership and control rights persist. |
| s30 | User1 added one device and sent an invitation; user2 scanned, accepted, and exercised device control, thereby becoming an active family member with uninterrupted rights. |
| s31 | User1 added a device and sent an invitation that was scanned, accepted, and led to device control by user2; even though user2 later quit home, as a family member the control rights remain (with the device still active, count = 1). |
| s32 | User1 added a device and sent repeated invitations (including a duplicate) that resulted in user2 scanning, accepting, and controlling the device; after user1 removed and re-added the device (final count = 1), user2 remains a family member with permanent control rights. |

