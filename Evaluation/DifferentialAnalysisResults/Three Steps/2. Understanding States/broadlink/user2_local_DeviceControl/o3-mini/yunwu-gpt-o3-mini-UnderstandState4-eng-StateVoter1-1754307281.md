# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device added and no invitation sent. |
| s1 | user1 added the device once; no invitation was initiated, so user2 has no permissions. |
| s2 | Error state. |
| s3 | user1 added the device once and sent an invitation for family membership; user2’s invitation is pending acceptance. |
| s4 | user1 issued an invitation without adding a device; user2’s invitation remains pending acceptance with no granted control. |
| s5 | user1 added the device and issued an invitation; user2 scanned the QR code but has not accepted, so no control rights are granted. |
| s6 | user1 added the device and sent an invitation; user2 scanned the QR code and accepted, thereby becoming a family member with permanent control rights. |
| s7 | user1 added the device once and sent a second invitation after an initial QR scan; user2 accepted the later invitation, establishing family membership with permanent control rights. |
| s8 | user1 sent an invitation without adding a device; user2 scanned and accepted the invitation, thus becoming a family member for future device additions. |
| s9 | user1 issued two sequential invitations without a device addition; after scanning and accepting the final invitation, user2 becomes a family member with control rights. |
| s10 | user1 sent an invitation and user2 scanned the QR code, but without final acceptance, user2 has not obtained control rights. |
| s11 | user1 added the device and issued an invitation that was accepted by user2, granting family membership; however, user2 later quit the home, revoking those control rights. |
| s12 | user1 issued an invitation without adding a device; user2 accepted the invitation and gained family membership, but later quit, thereby canceling the control rights. |
| s13 | user1 sent an invitation which was initially scanned by user2, followed by a re-issued invitation that was not accepted; as a result, user2’s invitation remains pending with no control granted. |
| s14 | user1 added the device and initiated an invitation process (including a QR scan), but a subsequent invitation went unaccepted, leaving user2’s status pending with no control rights. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state: no device has been added and no invitation has been sent; user2 has no permissions. |
| s1 | user1 added the device once (device count = 1) and no invitation was sent, so user2 remains uninvolved with no permissions. |
| s2 | Error state. |
| s3 | user1 sent an invitation (InviteToHome) without adding a device; user2’s invitation is pending (neither QR scanned nor accepted). |
| s4 | user1 sent an invitation and user2 scanned the QR code, leaving the invitation pending (not yet accepted) with no device added. |
| s5 | user1’s invitation was accepted (after QR scanning), making user2 a family member with permanent control rights; no device was added. |
| s6 | user1 issued two invitations (one issued after a QR scan) and user2 accepted the later invitation, making user2 a family member; no device was added. |
| s7 | user1 added the device once (device count = 1) and issued invitations that user2 scanned and accepted, granting user2 family membership with permanent control rights. |
| s8 | user1 added the device once (device count = 1) and user2 accepted the invitation, making user2 a family member with permanent (active) control rights. |
| s9 | user1 sent an invitation (without a device added) that user2 accepted, but user2 later quit home, revoking their family membership and control rights. |
| s10 | user1 added the device once (device count = 1) and initiated an invitation which was QR scanned but not yet accepted by user2; the invitation remains pending. |
| s11 | user1 added the device once (device count = 1) and issued an invitation, but with no response from user2 the invitation remains pending and no control is granted. |
| s12 | user1 added the device once (device count = 1) and user2 accepted the invitation, but user2 later quit home, resulting in loss of family membership and control rights. |
| s13 | user1 added the device once (device count = 1) and sent multiple invitations; although user2 scanned the QR code, the final invitation was not accepted, leaving user2’s membership pending. |
| s14 | user1 sent invitations without adding a device; user2 scanned the QR code, initiating the process, but without acceptance their status remains pending. |
| s15 | user1 added the device once (device count = 1) and completed the invitation process with user2 scanning and accepting, resulting in user2 becoming a family member actively controlling the device. |
| s16 | user1 added the device once (device count = 1) and user2 accepted the invitation; although the device was subsequently removed, user2’s family membership and control rights persist. |
| s17 | user1 added the device once (device count = 1) and user2 accepted and controlled the device; however, after the device was removed and user2 quit home, their family membership and control rights were lost. |
| s18 | user1 executed an add–remove–add sequence (ending with 1 active device) after user2 accepted and controlled the invitation; however, user2 subsequently quit home, thereby revoking their family membership and control rights. |
| s19 | user1 added the device once (device count = 1) and user2 accepted the invitation, but user2 later quit home, revoking their family membership and control rights. |
| s20 | user1 added the device once (device count = 1) and user2 accepted and controlled the device; however, after user2 quit home and rescanned the QR code, a new invitation is pending acceptance. |
| s21 | user1 performed an add–remove–add sequence (ending with 1 active device) following an accepted invitation; subsequently, user2 quit home and rescanned the QR code, resulting in a new invitation pending and loss of active family membership. |
| s22 | user1 added the device once but then removed it (device count becomes 0); although user2 had previously accepted the invitation, after quitting home and rescanning the QR code a new invitation is pending with no active control rights. |
| s23 | user1 added the device once and completed the invitation process (granting family membership), but then removed the device; after user2 quit home and rescanned the QR code, a new invitation is issued, leaving user2’s membership pending. |
| s24 | user1 performed a remove–add cycle resulting in one active device; after user2 (who had previously accepted) quit home, a new invitation was issued, leaving user2’s status pending acceptance. |
| s25 | user1 added the device once (device count = 1) and user2 initially accepted the invitation, but after quitting home and rescanning the QR code, a new invitation was issued, leaving user2’s status pending acceptance. |
| s26 | user1 added the device once and user2 accepted the invitation, becoming a family member; although the device was subsequently removed, user2 retains permanent control rights. |
| s27 | user1 added the device once and user2 accepted the invitation; however, after the device was removed and user2 quit home, user2 lost family membership and control rights. |
| s28 | user1 performed an add–remove–add sequence (resulting in one active device); although user2 initially accepted the invitation, a subsequent quit home revoked their family membership and control rights. |
| s29 | user1 added the device, removed it, and re-added it (ending with one active device) following an accepted invitation, and user2 remains a family member with permanent control rights. |
| s30 | user1 added the device once (device count = 1) and user2 accepted the invitation, thereby becoming a family member with permanent control rights that are actively exercised. |
| s31 | user1 added the device once (device count = 1) and user2 accepted the invitation and exercised control; however, a subsequent quit home action by user2 revokes family membership and control rights. |
| s32 | user1 performed an add–remove–add sequence (ending with one active device) and reissued an invitation that was accepted by user2; consequently, user2 remains a family member with permanent control rights. |

