# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state with no device added and no invitation sent. |
| s1 | user1 added one device instance (device addition count = 1) without initiating any invitation; user2 remains uninvited and without control rights. |
| s2 | Error state. |
| s3 | user1 added one device instance and sent a family invitation; user2 is invited but has not yet accepted, so no control rights are granted. |
| s4 | user1 issued a family invitation without adding a device; user2 is invited (pending acceptance) and no device is present in this sequence. |
| s5 | user1 added one device instance and sent a family invitation; user2 scanned the QR code but has not yet accepted, leaving the sharing action pending. |
| s6 | user1 added one device instance and sent a family invitation; after scanning and accepting, user2 becomes a family member with permanent control rights. |
| s7 | user1 added one device instance and issued two invitations (a re-invitation); user2 scanned and accepted the latter invitation, establishing family membership with permanent control rights. |
| s8 | user1 sent a family invitation without adding a device; user2 scanned and accepted it, thereby becoming a family member with control rights for future device additions. |
| s9 | user1 issued multiple family invitations without adding a device; user2 scanned and accepted the final invitation, obtaining family member status with permanent control rights. |
| s10 | user1 sent a family invitation; user2 scanned the QR code but did not complete acceptance, so no control rights are granted. |
| s11 | user1 added one device instance and sent a family invitation; user2 scanned and accepted to gain family membership but later quit, thereby relinquishing their control rights. |
| s12 | user1 sent a family invitation without adding a device; user2 accepted but then quit, resulting in the revocation of control rights. |
| s13 | user1 issued an invitation and then re-sent a family invitation after a QR scan by user2; without a subsequent final acceptance, user2’s family membership remains unconfirmed and no control is granted. |
| s14 | user1 added one device instance and issued multiple family invitations; although user2 scanned a QR code, the absence of final acceptance means no control rights are granted. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device has been added and no invitation has been initiated; user2 is not involved. |
| s1 | user1 added the device (device count = 1) with no invitation initiated, so user2 holds no permission. |
| s2 | Error state. |
| s3 | user1 sent an invitation (InviteToHome) without adding a device; user2’s invitation remains pending acceptance. |
| s4 | user1 initiated an invitation and user2 scanned the QR code, but user2 has not yet accepted the invitation. |
| s5 | user1 issued an invitation that user2 scanned and accepted, thereby establishing family membership with permanent control; no device was added. |
| s6 | user1 performed two invitation actions (with a QR scan in between) and user2 accepted the latter invitation, resulting in user2 becoming a family member even though no device was added. |
| s7 | user1 added the device (device count = 1) and completed the invitation process (via QR scan and acceptance), conferring permanent family membership and control to user2. |
| s8 | user1 added the device (device count = 1) and invited user2, who scanned and accepted the invitation, thereby establishing family membership with control over that instance. |
| s9 | user1 sent an invitation that user2 scanned and accepted, but user2 then QuitHome; however, as a family member, user2’s permanent control rights persist despite the inactive session. |
| s10 | user1 added the device (device count = 1) and sent an invitation; user2 scanned the QR code but has not yet accepted, leaving the sharing process pending. |
| s11 | user1 added the device (device count = 1) and initiated an invitation, but user2 has not taken any action, so permission remains ungranted. |
| s12 | user1 added the device (device count = 1) and completed the invitation process by having user2 scan and accept; although user2 later QuitHome, family membership and permanent control remain effective. |
| s13 | user1 added the device (device count = 1) and initiated an invitation that was reissued after a QR scan, but user2 has not completed the acceptance, so the sharing process remains pending. |
| s14 | Without any device added, user1 issued invitation actions (including a QR scan and a re-invite), yet user2 has not accepted the invitation, leaving the status pending. |
| s15 | user1 added the device (device count = 1) and conducted the invitation process (QR scan followed by acceptance), enabling user2 to exercise control as an active family member. |
| s16 | user1 added the device (device count = 1) and completed the invitation process; although user1 later removed the device, user2’s permanent family membership and control rights persist. |
| s17 | user1 added the device (device count = 1) and completed the invitation process; after user1 removed the device, user2 QuitHome, yet family membership and permanent control rights remain intact. |
| s18 | user1 added the device, then removed it and re-added it (final device count = 1) after user2 had accepted the invitation; although user2 later QuitHome, family membership continues. |
| s19 | user1 added the device (device count = 1) and completed the invitation process; user2 accepted and exercised control, and even after quitting home, their permanent family membership is retained. |
| s20 | user1 added the device (device count = 1) and finalized the invitation process, granting family membership; although user2 QuitHome and then re-scanned the QR code, acceptance remains in effect with permanent control rights intact. |
| s21 | user1 added the device, then removed and re-added it (final device count = 1), and completed the invitation process; user2, after initially exercising control, QuitHome and rescanned the QR code—indicating a pending session restart while permanent family membership endures. |
| s22 | user1 added the device and then removed it (resulting in a device count of 0) after the invitation was accepted; following a subsequent QR scan by user2 after quitting home, the reactivation is pending even though family membership persists. |
| s23 | user1 added the device and completed the invitation process, then removed the device; after user2 QuitHome and scanned the QR code, a new invitation was issued, reinitiating the sharing process while the original family membership remains. |
| s24 | user1 added the device, then removed it and re-added it (final device count = 1) following an accepted invitation; after user2 QuitHome and scanned the QR code, a new invitation was triggered even though user2’s family membership persists. |
| s25 | user1 added the device (device count = 1) and completed the invitation process, with user2 accepting and exercising control; later, user2 QuitHome and rescanned the QR code, prompting a new invitation that leaves the session pending while permanent rights remain. |
| s26 | user1 added the device (device count = 1) and user2 accepted the invitation—gaining family membership and control; even though the device was later removed, user2’s permanent rights continue. |
| s27 | user1 added the device (device count = 1) and completed the invitation process; after subsequent removal of the device and user2 quitting home, family membership and permanent control rights persist. |
| s28 | user1 added the device, then removed and re-added it (final device count = 1) following an accepted invitation; although user2 later QuitHome, family membership remains in force. |
| s29 | user1 added the device (device count = 1) and completed the invitation process; even after the device was removed and re-added, user2’s family membership and control rights continue. |
| s30 | user1 added the device (device count = 1) and sent an invitation that was scanned and accepted by user2, who now exercises active control as a family member. |
| s31 | user1 added the device (device count = 1) and completed the invitation process; even though user2 initially exercised control, they later QuitHome, the family membership and permanent rights remain effective. |
| s32 | user1 added the device (after a removal and re-addition resulting in a device count = 1) and reissued an invitation that user2 previously scanned and accepted, so user2 retains permanent family membership with active control rights. |

